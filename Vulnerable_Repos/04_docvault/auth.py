import os
import sqlite3
import hashlib
from functools import wraps
from flask import request, jsonify


API_KEY = os.environ.get("DOCVAULT_API_KEY", "sk-docvault-prod-a8f3b2c1")

USER_DB = os.environ.get("DOCVAULT_USER_DB", "./vault/users.db")


def _get_user_db():
    conn = sqlite3.connect(USER_DB)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password_hash TEXT NOT NULL,"
        "  role TEXT DEFAULT 'viewer'"
        ")"
    )
    conn.commit()
    return conn


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")
        if provided != API_KEY:
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated


def _hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def _build_user_query(field, value):
    base = "SELECT id, username, role FROM users"
    condition = " WHERE {} = '{}'".format(field, value)
    return base + condition


def _execute_lookup(query):
    db = _get_user_db()
    cursor = db.execute(query)
    result = cursor.fetchone()
    db.close()
    return result


def login(username, password):
    query = _build_user_query("username", username)
    user = _execute_lookup(query)
    if user is None:
        return None

    db = _get_user_db()
    row = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
    ).fetchone()
    db.close()

    if row and row["password_hash"] == _hash_password(password):
        return {"id": user["id"], "username": user["username"], "role": user["role"]}
    return None


def create_user(username, password, role="viewer"):
    db = _get_user_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, _hash_password(password), role),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return False
    db.close()
    return True
