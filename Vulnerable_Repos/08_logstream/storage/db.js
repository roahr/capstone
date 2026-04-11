const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs-extra");

function initDatabase(dbPath) {
  fs.ensureDirSync(path.dirname(dbPath));
  const db = new Database(dbPath);

  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      level TEXT DEFAULT 'info',
      message TEXT NOT NULL,
      metadata TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at)`);

  return db;
}

function insertLog(db, entry) {
  const stmt = db.prepare(
    "INSERT INTO logs (source, level, message, metadata) VALUES (?, ?, ?, ?)"
  );
  return stmt.run(entry.source, entry.level, entry.message, entry.metadata);
}

function executeQuery(db, sql) {
  return db.prepare(sql).all();
}

function getLogCount(db) {
  return db.prepare("SELECT COUNT(*) as total FROM logs").get().total;
}

function purgeBefore(db, date) {
  return db.prepare("DELETE FROM logs WHERE created_at < ?").run(date);
}

module.exports = { initDatabase, insertLog, executeQuery, getLogCount, purgeBefore };
