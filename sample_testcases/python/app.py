"""
SecureNotes — Main Flask Application

A lightweight note-taking REST API with JWT authentication, file upload /
download, and full-text search.

Routes:
    POST   /auth/register      — Create a new account
    POST   /auth/login          — Obtain a bearer token
    GET    /notes               — List the current user's notes
    POST   /notes               — Create a note
    GET    /notes/<id>          — Retrieve a single note
    PUT    /notes/<id>          — Update a note
    DELETE /notes/<id>          — Delete a note
    GET    /notes/search        — Full-text title search
    GET    /notes/recent        — Notes from the last N days
    GET    /search              — HTML search results page
    GET    /download/<filename> — Download an uploaded file
    GET    /avatar/<username>   — Serve a user's avatar image
    POST   /notes/export        — Export notes to tarball
"""

import os
from flask import Flask, request, jsonify, send_file, g

import db
import auth
import utils

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit

UPLOAD_DIR = os.environ.get("SECURENOTES_UPLOADS", "/var/data/securenotes/uploads")


# ── Lifecycle ──────────────────────────────────────────────────────────────

@app.before_request
def _ensure_db():
    """Initialise the database on first request."""
    if not getattr(app, "_db_initialised", False):
        db.init_db()
        app._db_initialised = True


# ── Auth routes ────────────────────────────────────────────────────────────

@app.route("/auth/register", methods=["POST"])
def register():
    """Register a new user account."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    email = data.get("email", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    result = auth.register_user(username, password, email)
    if isinstance(result, tuple):
        return jsonify(result[0]), result[1]
    return jsonify(result), 201


@app.route("/auth/login", methods=["POST"])
def login():
    """Authenticate and return a bearer token."""
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    result = auth.login_user(username, password)
    if isinstance(result, tuple):
        return jsonify(result[0]), result[1]
    return jsonify(result)


# ── Note CRUD ──────────────────────────────────────────────────────────────

@app.route("/notes", methods=["GET"])
@auth.login_required
def list_notes():
    """Return all notes belonging to the authenticated user."""
    notes = db.search_notes("", g.current_user["user_id"])
    return jsonify(notes)


@app.route("/notes", methods=["POST"])
@auth.login_required
def create_note():
    """Create a new note for the authenticated user."""
    data = request.get_json(force=True)
    title = data.get("title", "").strip()
    body = data.get("body", "")

    if not title:
        return jsonify({"error": "Title is required"}), 400

    note_id = db.create_note(g.current_user["user_id"], title, body)
    return jsonify({"id": note_id, "title": title}), 201


@app.route("/notes/<int:note_id>", methods=["GET"])
@auth.login_required
def get_note(note_id: int):
    """Retrieve a single note by ID."""
    note = db.get_note_by_id(note_id)
    if note is None:
        return jsonify({"error": "Note not found"}), 404
    return jsonify(note)


@app.route("/notes/<int:note_id>", methods=["PUT"])
@auth.login_required
def update_note(note_id: int):
    """Update an existing note."""
    data = request.get_json(force=True)
    title = data.get("title", "").strip()
    body = data.get("body", "")

    if not title:
        return jsonify({"error": "Title is required"}), 400

    if db.update_note(note_id, title, body):
        return jsonify({"id": note_id, "title": title})
    return jsonify({"error": "Note not found"}), 404


@app.route("/notes/<int:note_id>", methods=["DELETE"])
@auth.login_required
def delete_note(note_id: int):
    """Delete a note by ID."""
    if db.delete_note(note_id):
        return "", 204
    return jsonify({"error": "Note not found"}), 404


# ── Search ─────────────────────────────────────────────────────────────────

@app.route("/notes/search", methods=["GET"])
@auth.login_required
def search_notes():
    """Search notes by title substring (JSON API)."""
    query = request.args.get("q", "")
    results = db.search_notes(query, g.current_user["user_id"])
    return jsonify(results)


@app.route("/notes/recent", methods=["GET"])
@auth.login_required
def recent_notes():
    """Return notes created in the last N days (default 7)."""
    days = request.args.get("days", "7")
    results = db.get_recent_notes(days, g.current_user["user_id"])
    return jsonify(results)


# ---------------------------------------------------------------------------
# TRUE POSITIVE: CWE-79 Cross-Site Scripting (Reflected XSS)
# The `query` parameter is embedded directly into an HTML string without
# escaping.  An attacker can inject arbitrary JavaScript via the q param.
# ---------------------------------------------------------------------------
@app.route("/search", methods=["GET"])
def search_page():
    """Render an HTML search results page (public)."""
    query = request.args.get("q", "")
    results = db.search_notes(query, user_id=0)
    html_parts = [f"<h2>Results for: {query}</h2>", "<ul>"]
    for note in results:
        html_parts.append(f"<li>{utils.sanitize_html(note['title'])}</li>")
    html_parts.append("</ul>")
    return "\n".join(html_parts), 200, {"Content-Type": "text/html"}


# ── File serving ───────────────────────────────────────────────────────────

# ---------------------------------------------------------------------------
# TRUE POSITIVE: CWE-22 Path Traversal
# `filename` can contain `../` sequences, letting an attacker read any
# file on the server that the process user can access.
# ---------------------------------------------------------------------------
@app.route("/download/<path:filename>", methods=["GET"])
@auth.login_required
def download_file(filename: str):
    """Serve an uploaded file by name."""
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404
    return send_file(filepath, as_attachment=True)


# ---------------------------------------------------------------------------
# FALSE POSITIVE #10: CWE-22 — realpath + prefix check
# (Contextual tier, Graph resolves)
# Even though `username` reaches os.path.join, the resolved path is
# validated against UPLOAD_DIR with os.path.realpath and startswith before
# any file I/O.  A graph-level data-flow analysis would see the guard
# dominates the send_file call.
# ---------------------------------------------------------------------------
@app.route("/avatar/<username>", methods=["GET"])
def serve_avatar(username: str):
    """Serve a user's avatar image with path traversal protection."""
    avatar_dir = os.path.join(UPLOAD_DIR, "avatars")
    candidate = os.path.join(avatar_dir, f"{username}.png")
    real_path = os.path.realpath(candidate)

    if not real_path.startswith(os.path.realpath(avatar_dir)):
        return jsonify({"error": "Invalid path"}), 400

    if not os.path.isfile(real_path):
        return jsonify({"error": "Avatar not found"}), 404

    return send_file(real_path, mimetype="image/png")


# ── Export ─────────────────────────────────────────────────────────────────

@app.route("/notes/export", methods=["POST"])
@auth.login_required
def export_notes():
    """Export all notes to a tarball archive."""
    data = request.get_json(force=True)
    filename = data.get("filename", "notes_export")
    success = utils.export_notes(filename)
    if success:
        return jsonify({"status": "ok", "filename": f"{filename}.tar.gz"})
    return jsonify({"error": "Export failed"}), 500


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
