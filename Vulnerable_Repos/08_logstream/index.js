const express = require("express");
const morgan = require("morgan");
const path = require("path");
const fs = require("fs-extra");

const queryHandler = require("./handlers/query");
const exportHandler = require("./handlers/export");
const { initDatabase, insertLog } = require("./storage/db");

const app = express();
const PORT = process.env.PORT || 3900;
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, "logs");

fs.ensureDirSync(LOG_DIR);

const db = initDatabase(path.join(__dirname, "data", "logs.db"));

app.use(morgan("short"));
app.use(express.json({ limit: "2mb" }));

app.post("/ingest", (req, res) => {
  const { source, level, message, metadata } = req.body;

  if (!source || !message) {
    return res.status(400).json({ error: "source and message are required" });
  }

  const entry = insertLog(db, {
    source,
    level: level || "info",
    message,
    metadata: JSON.stringify(metadata || {}),
  });

  res.status(201).json({ id: entry.lastInsertRowid, status: "ingested" });
});

app.get("/query", (req, res) => queryHandler(db, req, res));
app.get("/export", (req, res) => exportHandler.download(db, req, res, LOG_DIR));
app.post("/rotate", (req, res) => exportHandler.rotate(req, res, LOG_DIR));

app.get("/health", (req, res) => {
  res.json({ status: "ok", logDir: LOG_DIR, uptime: process.uptime() });
});

app.use((err, req, res, _next) => {
  console.error(`[logstream] ${err.message}`);
  res.status(500).json({ error: "Internal error" });
});

app.listen(PORT, () => {
  console.log(`LogStream listening on port ${PORT}`);
});

module.exports = app;
