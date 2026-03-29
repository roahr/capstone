/**
 * TaskBoard — Express micro-app for task management.
 *
 * Boots the HTTP server, wires middleware, mounts route modules,
 * and initialises the SQLite database on first run.
 */

const express = require("express");
const path = require("path");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;

// TP-6  CWE-798: Hardcoded JWT signing secret used in production paths.
const JWT_SECRET = "my-super-secret-jwt-key-2024";

// FP-12 CWE-798: Looks like a hardcoded secret, but the guard below ensures
//       it is never actually used in production without being overridden.
const SESSION_KEY = process.env.SESSION_KEY || "change-me-in-production";
if (process.env.NODE_ENV === "production" && SESSION_KEY === "change-me-in-production") {
  throw new Error(
    "SESSION_KEY must be set via environment variable in production. " +
    "Refusing to start with the default placeholder value."
  );
}

// ---------------------------------------------------------------------------
// Database bootstrap
// ---------------------------------------------------------------------------

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "taskboard.db");

function initDatabase() {
  const db = new Database(DB_PATH);

  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         TEXT PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      avatar     TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id          TEXT PRIMARY KEY,
      title       TEXT NOT NULL,
      description TEXT,
      status      TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','done')),
      priority    INTEGER DEFAULT 0,
      assignee_id TEXT REFERENCES users(id),
      created_at  TEXT DEFAULT (datetime('now')),
      updated_at  TEXT DEFAULT (datetime('now'))
    );
  `);

  return db;
}

const db = initDatabase();

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.url}`);
  next();
});

// ---------------------------------------------------------------------------
// Auth middleware — uses the hardcoded JWT_SECRET (TP-6)
// ---------------------------------------------------------------------------

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

// Quick token-issuing endpoint (dev convenience)
app.post("/auth/login", (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: "username is required" });
  }

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const token = jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "8h",
  });
  return res.json({ token });
});

// Session-based fallback (uses SESSION_KEY, the safe one — FP-12)
app.use((req, _res, next) => {
  if (req.cookies && req.cookies.session) {
    try {
      req.session = jwt.verify(req.cookies.session, SESSION_KEY);
    } catch {
      req.session = null;
    }
  }
  next();
});

// ---------------------------------------------------------------------------
// Route mounting
// ---------------------------------------------------------------------------

const taskRoutes = require("./routes/tasks");
const userRoutes = require("./routes/users");

app.use("/tasks", authenticateToken, taskRoutes(db));
app.use("/users", authenticateToken, userRoutes(db));

// Health-check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------

app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`TaskBoard API listening on http://localhost:${PORT}`);
  });
}

module.exports = { app, db };
