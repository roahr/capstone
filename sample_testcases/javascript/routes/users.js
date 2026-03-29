/**
 * routes/users.js — User management routes for TaskBoard.
 *
 * Handles user CRUD and avatar file serving.
 */

const { Router } = require("express");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const UPLOAD_DIR = path.resolve(__dirname, "..", "data", "avatars");
const STATIC_ASSETS_DIR = path.resolve(__dirname, "..", "public", "assets");

// Ensure the upload directory exists at startup
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

module.exports = function userRoutes(db) {
  const router = Router();

  // -----------------------------------------------------------------------
  // GET /users — list users
  // -----------------------------------------------------------------------
  router.get("/", (_req, res) => {
    try {
      const users = db.prepare("SELECT id, username, email, created_at FROM users").all();
      return res.json({ users });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // GET /users/:id
  // -----------------------------------------------------------------------
  router.get("/:id", (req, res) => {
    const { id } = req.params;

    try {
      const user = db.prepare("SELECT id, username, email, avatar, created_at FROM users WHERE id = ?").get(id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      return res.json({ user });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // POST /users — create user
  // -----------------------------------------------------------------------
  router.post("/", (req, res) => {
    const { username, email } = req.body;

    if (!username || !email) {
      return res.status(400).json({ error: "username and email are required" });
    }

    const id = uuidv4();

    try {
      db.prepare("INSERT INTO users (id, username, email) VALUES (?, ?, ?)").run(id, username, email);
      const user = db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?").get(id);
      return res.status(201).json({ user });
    } catch (err) {
      if (err.message.includes("UNIQUE")) {
        return res.status(409).json({ error: "Username or email already exists" });
      }
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // DELETE /users/:id
  // -----------------------------------------------------------------------
  router.delete("/:id", (req, res) => {
    const { id } = req.params;

    try {
      const info = db.prepare("DELETE FROM users WHERE id = ?").run(id);
      if (info.changes === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -----------------------------------------------------------------------
  // GET /users/:id/avatar
  // TP-4  CWE-22 (Path Traversal)
  //
  // The `filename` query parameter is joined to UPLOAD_DIR without any
  // sanitisation.  A request like  ?filename=../../etc/passwd  escapes
  // the intended directory and reads arbitrary files from the server.
  // -----------------------------------------------------------------------
  router.get("/:id/avatar", (req, res) => {
    const filename = req.query.filename || "default.png";

    // VULNERABLE: no validation on filename — directory traversal possible
    const filePath = path.join(UPLOAD_DIR, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Avatar not found" });
    }

    return res.sendFile(filePath);
  });

  // -----------------------------------------------------------------------
  // GET /users/assets/:name
  // FP-10  CWE-22 (False positive — path is validated)
  //
  // SAST flags `path.resolve` + `sendFile`, but the resolved path is
  // checked to ensure it stays within STATIC_ASSETS_DIR before serving.
  // -----------------------------------------------------------------------
  router.get("/assets/:name", (req, res) => {
    const requestedName = req.params.name;
    const resolvedPath = path.resolve(STATIC_ASSETS_DIR, requestedName);

    // Guard: resolved path must start with the allowed directory
    if (!resolvedPath.startsWith(STATIC_ASSETS_DIR + path.sep)) {
      return res.status(403).json({ error: "Access denied" });
    }

    if (!fs.existsSync(resolvedPath)) {
      return res.status(404).json({ error: "Asset not found" });
    }

    return res.sendFile(resolvedPath);
  });

  // -----------------------------------------------------------------------
  // PATCH /users/:id
  // -----------------------------------------------------------------------
  router.patch("/:id", (req, res) => {
    const { id } = req.params;
    const allowed = ["username", "email", "avatar"];
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

    values.push(id);

    try {
      const info = db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).run(...values);
      if (info.changes === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      const user = db.prepare("SELECT id, username, email, avatar, created_at FROM users WHERE id = ?").get(id);
      return res.json({ user });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  return router;
};
