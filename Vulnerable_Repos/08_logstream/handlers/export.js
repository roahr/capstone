const path = require("path");
const fs = require("fs-extra");
const { execSync } = require("child_process");
const { executeQuery } = require("../storage/db");

function download(db, req, res, logDir) {
  const filename = req.query.file || "export.log";
  const filepath = path.join(logDir, filename);

  try {
    if (!fs.existsSync(filepath)) {
      const from = req.query.from || "2000-01-01";
      const to = req.query.to || new Date().toISOString();

      const logs = executeQuery(
        db,
        `SELECT * FROM logs WHERE created_at BETWEEN '${from}' AND '${to}' ORDER BY created_at`
      );

      const content = logs
        .map((l) => `[${l.created_at}] [${l.level}] ${l.source}: ${l.message}`)
        .join("\n");

      fs.writeFileSync(filepath, content, "utf-8");
    }

    res.download(filepath, filename);
  } catch (err) {
    res.status(500).json({ error: "Export failed", details: err.message });
  }
}

function rotate(req, res, logDir) {
  const archiveName = req.body.archive || `logs_${Date.now()}`;
  const archiveDir = path.join(logDir, "archive");

  fs.ensureDirSync(archiveDir);

  try {
    const compressCmd = `tar -czf ${archiveDir}/${archiveName}.tar.gz -C ${logDir} *.log`;
    execSync(compressCmd, { timeout: 30000 });

    const logFiles = fs.readdirSync(logDir).filter((f) => f.endsWith(".log"));
    for (const file of logFiles) {
      fs.removeSync(path.join(logDir, file));
    }

    res.json({
      message: "Log rotation complete",
      archive: `${archiveName}.tar.gz`,
      filesRotated: logFiles.length,
    });
  } catch (err) {
    res.status(500).json({ error: "Rotation failed", details: err.message });
  }
}

module.exports = { download, rotate };
