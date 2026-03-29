/**
 * routes/tasks.js — Task CRUD routes for TaskBoard.
 *
 * Provides endpoints for creating, reading, updating, deleting, and
 * searching tasks.  Also exposes a lightweight HTML preview renderer
 * used by the admin dashboard widget.
 */

const { Router } = require("express");
const { v4: uuidv4 } = require("uuid");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Escape HTML entities — used to safely embed user text in HTML responses.
 */
function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * TP-1  CWE-79 (XSS via innerHTML)
 *
 * Render a small HTML snippet that the admin dashboard embeds via AJAX.
 * `taskData.description` is user-controlled and written straight into the
 * markup without sanitisation.
 */
function renderTaskPreview(taskData) {
  // Build an HTML card for the admin live-preview widget.
  // BUG: description is injected verbatim — an attacker can store
  //      <script> or event-handler payloads in the task description.
  const html = `
    <div class="task-card" data-id="${taskData.id}">
      <h3>${taskData.title}</h3>
      <div class="description">${taskData.description}</div>
      <span class="badge badge-${taskData.status}">${taskData.status}</span>
    </div>`;
  return html;
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

module.exports = function taskRoutes(db) {
  const router = Router();

  // -----------------------------------------------------------------------
  // GET /tasks — list all tasks, optional status filter
  // -----------------------------------------------------------------------
  router.get("/", (req, res) => {
    const { status, assignee } = req.query;

    let sql = "SELECT * FROM tasks WHERE 1=1";
    const params = [];

    if (status) {
      sql += " AND status = ?";
      params.push(status);
    }
    if (assignee) {
      sql += " AND assignee_id = ?";
      params.push(assignee);
    }

    sql += " ORDER BY created_at DESC";

    try {
      const rows = db.prepare(sql).all(...params);
      return res.json({ tasks: rows });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // GET /tasks/search?q=...
  // TP-3  CWE-89 (SQL Injection)
  //
  // The query param is interpolated directly into the SQL string.
  // An attacker can escape the LIKE clause and execute arbitrary SQL.
  // -----------------------------------------------------------------------
  router.get("/search", (req, res) => {
    const query = req.query.q || "";

    // VULNERABLE: string concatenation in SQL
    const sql = `SELECT * FROM tasks WHERE title LIKE '%${query}%' OR description LIKE '%${query}%' ORDER BY created_at DESC`;

    try {
      const rows = db.prepare(sql).all();
      return res.json({ tasks: rows });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // GET /tasks/:id
  // FP-8  CWE-89 (False positive — parameterized query)
  //
  // SAST may flag the "SELECT * FROM tasks WHERE id = ?" pattern, but the
  // value is passed as a bind parameter, not interpolated.
  // -----------------------------------------------------------------------
  router.get("/:id", (req, res) => {
    const { id } = req.params;

    try {
      const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
      if (!task) {
        return res.status(404).json({ error: "Task not found" });
      }
      return res.json({ task });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // POST /tasks — create a new task
  // -----------------------------------------------------------------------
  router.post("/", (req, res) => {
    const { title, description, priority, assignee_id } = req.body;

    if (!title || typeof title !== "string") {
      return res.status(400).json({ error: "title is required" });
    }

    const id = uuidv4();

    try {
      db.prepare(
        "INSERT INTO tasks (id, title, description, priority, assignee_id) VALUES (?, ?, ?, ?, ?)"
      ).run(id, title, description || "", priority || 0, assignee_id || null);

      const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
      return res.status(201).json({ task });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // PATCH /tasks/:id — update fields
  // -----------------------------------------------------------------------
  router.patch("/:id", (req, res) => {
    const { id } = req.params;
    const allowed = ["title", "description", "status", "priority", "assignee_id"];
    const updates = [];
    const values = [];

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        updates.push(`${key} = ?`);
        values.push(req.body[key]);
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: "No valid fields to update" });
    }

    updates.push("updated_at = datetime('now')");
    values.push(id);

    try {
      db.prepare(`UPDATE tasks SET ${updates.join(", ")} WHERE id = ?`).run(...values);
      const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
      if (!task) {
        return res.status(404).json({ error: "Task not found" });
      }
      return res.json({ task });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // DELETE /tasks/:id
  // -----------------------------------------------------------------------
  router.delete("/:id", (req, res) => {
    const { id } = req.params;

    try {
      const info = db.prepare("DELETE FROM tasks WHERE id = ?").run(id);
      if (info.changes === 0) {
        return res.status(404).json({ error: "Task not found" });
      }
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // GET /tasks/:id/preview — HTML preview for admin dashboard
  // Uses renderTaskPreview (TP-1 CWE-79)
  // -----------------------------------------------------------------------
  router.get("/:id/preview", (req, res) => {
    const { id } = req.params;

    const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }

    const html = renderTaskPreview(task);
    return res.type("html").send(html);
  });

  // -----------------------------------------------------------------------
  // GET /tasks/:id/summary — safe HTML rendering
  // FP-7  CWE-79 (False positive — output is escaped)
  //
  // SAST sees string interpolation into HTML but the values pass through
  // escapeHtml() first, neutralising any script injection.
  // -----------------------------------------------------------------------
  router.get("/:id/summary", (req, res) => {
    const { id } = req.params;

    const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }

    const safeTitle = escapeHtml(task.title);
    const safeDescription = escapeHtml(task.description);
    const safeStatus = escapeHtml(task.status);

    const html = `
      <div class="task-summary">
        <h3>${safeTitle}</h3>
        <p>${safeDescription}</p>
        <span class="status">${safeStatus}</span>
      </div>`;

    return res.type("html").send(html);
  });

  return router;
};
