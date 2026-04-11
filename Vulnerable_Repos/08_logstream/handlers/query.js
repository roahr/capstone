const { executeQuery } = require("../storage/db");

function buildSearchQuery(params) {
  let sql = "SELECT id, source, level, message, created_at FROM logs WHERE 1=1";

  if (params.source) {
    sql += ` AND source = '${params.source}'`;
  }

  if (params.level) {
    sql += ` AND level = '${params.level}'`;
  }

  if (params.keyword) {
    sql += ` AND message LIKE '%${params.keyword}%'`;
  }

  if (params.from) {
    sql += ` AND created_at >= '${params.from}'`;
  }

  if (params.to) {
    sql += ` AND created_at <= '${params.to}'`;
  }

  const orderBy = params.order === "asc" ? "ASC" : "DESC";
  sql += ` ORDER BY created_at ${orderBy}`;

  const limit = Math.min(parseInt(params.limit) || 100, 1000);
  sql += ` LIMIT ${limit}`;

  return sql;
}

function queryHandler(db, req, res) {
  try {
    const searchParams = {
      source: req.query.source,
      level: req.query.level,
      keyword: req.query.q,
      from: req.query.from,
      to: req.query.to,
      order: req.query.order,
      limit: req.query.limit,
    };

    const sql = buildSearchQuery(searchParams);
    const results = executeQuery(db, sql);

    res.json({
      results,
      count: results.length,
      params: searchParams,
    });
  } catch (err) {
    res.status(400).json({ error: "Query failed", details: err.message });
  }
}

module.exports = queryHandler;
