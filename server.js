
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// Database connection
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Frontend access
const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Authentication rate limit
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "تعداد تلاش‌ها زیاد است. کمی بعد دوباره امتحان کنید." }
});

// Create users table

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(30) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Add referral system columns without deleting existing users
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20)
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS referred_by BIGINT
    REFERENCES users(id) ON DELETE SET NULL
  `);

  // Generate codes for existing users
  await pool.query(`
    UPDATE users
    SET referral_code =
      'DOTO' || UPPER(
        SUBSTRING(
          MD5(RANDOM()::TEXT || id::TEXT || CLOCK_TIMESTAMP()::TEXT)
          FROM 1 FOR 10
        )
      )
    WHERE referral_code IS NULL
  `);

  // Ensure every referral code is unique
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_referral_code_unique
    ON users(referral_code)
  `);
}


// Create JWT
function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
}

// Authentication middleware
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "ابتدا وارد حساب شوید." });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "نشست شما معتبر نیست." });
  }
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "DOTO API" });
});

// Register
app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (
      typeof username !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "اطلاعات نامعتبر است." });
    }

    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(cleanUsername)) {
      return res.status(400).json({
        error: "نام کاربری باید ۳ تا ۳۰ حرف و شامل حروف انگلیسی، عدد یا _ باشد."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
        cleanEmail.length > 255) {
      return res.status(400).json({ error: "ایمیل معتبر نیست." });
    }

    if (password.length < 12 || password.length > 72) {
      return res.status(400).json({
        error: "رمز عبور باید حداقل ۱۲ و حداکثر ۷۲ کاراکتر باشد."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [cleanUsername, cleanEmail, passwordHash]
    );

    const user = result.rows[0];
    const token = createToken(user);

    res.status(201).json({
      message: "حساب کاربری ساخته شد.",
      token,
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "این نام کاربری یا ایمیل قبلاً ثبت شده است."
      });
    }

    console.error("Register error:", error.message);
    res.status(500).json({ error: "خطای داخلی سرور." });
  }
});

// Login
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "اطلاعات ورود نامعتبر است." });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, username, email, password_hash, created_at
       FROM users WHERE email = $1`,
      [cleanEmail]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است." });
    }

    const token = createToken(user);

    res.json({
      message: "ورود موفق بود.",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "خطای داخلی سرور." });
  }
});

// Current user
app.get("/api/auth/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, created_at
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "کاربر پیدا نشد." });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error("User lookup error:", error.message);
    res.status(500).json({ error: "خطای داخلی سرور." });
  }
});

// Start server
const PORT = process.env.PORT || 10000;

initializeDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`DOTO API running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  });
