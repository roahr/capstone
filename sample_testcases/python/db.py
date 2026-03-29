"""
SecureNotes — Database Operations Module

Handles all SQLite interactions for the note-taking API:
  - CRUD operations on notes
  - Full-text search
  - User data queries

Uses sqlite3 with a connection pool pattern for thread safety.
"""

import sqlite3
import os
from contextlib import contextmanager
from typing import Optional

DATABASE_PATH = os.environ.get("SECURENOTES_DB", "securenotes.db")


@contextmanager
def get_connection():
    """Yield a database connection with automatic commit/rollback."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they don't already exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
            CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_at);
        """)


# ---------------------------------------------------------------------------
# TRUE POSITIVE: CWE-89 SQL Injection
# The user-supplied `user_query` is interpolated directly into SQL via
# f-string formatting, allowing an attacker to break out of the LIKE
# clause and execute arbitrary SQL.
# ---------------------------------------------------------------------------
def search_notes(user_query: str, user_id: int) -> list[dict]:
    """Search notes by title (full-text match).

    Args:
        user_query: Free-text search term from the user.
        user_id: Authenticated user's ID.

    Returns:
        List of matching note dicts.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        sql = f"SELECT * FROM notes WHERE user_id = {user_id} AND title LIKE '%{user_query}%'"
        cursor.execute(sql)
        return [dict(row) for row in cursor.fetchall()]


# ---------------------------------------------------------------------------
# FALSE POSITIVE #7: CWE-89 — Parameterized query (Basic tier, SAST resolves)
# SAST may flag the `SELECT … WHERE id = ?` pattern, but the value is
# bound via a parameter tuple — no injection is possible.
# ---------------------------------------------------------------------------
def get_note_by_id(note_id: int) -> Optional[dict]:
    """Fetch a single note by its primary key.

    Uses parameterized query — safe from SQL injection.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# FALSE POSITIVE #9: CWE-89 — int() cast before interpolation
# (Contextual tier, Graph resolves)
# The f-string looks dangerous, but `int(days)` guarantees only a numeric
# literal reaches the query.  A graph analysis that tracks the cast would
# recognise this is safe.
# ---------------------------------------------------------------------------
def get_recent_notes(days, user_id: int) -> list[dict]:
    """Return notes created within the last N days.

    Args:
        days: Number of days to look back (converted to int for safety).
        user_id: Authenticated user's ID.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        safe_days = int(days)
        sql = f"SELECT * FROM notes WHERE user_id = {user_id} AND created_at > datetime('now', '-{safe_days} days')"
        cursor.execute(sql)
        return [dict(row) for row in cursor.fetchall()]


def create_note(user_id: int, title: str, body: str) -> int:
    """Insert a new note and return its ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (user_id, title, body),
        )
        return cursor.lastrowid


def update_note(note_id: int, title: str, body: str) -> bool:
    """Update an existing note. Returns True if a row was modified."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notes SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (title, body, note_id),
        )
        return cursor.rowcount > 0


def delete_note(note_id: int) -> bool:
    """Delete a note by ID. Returns True if a row was removed."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        return cursor.rowcount > 0


def get_user_by_username(username: str) -> Optional[dict]:
    """Look up a user record by username (parameterized)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None


def create_user(username: str, password_hash: str, email: str = "") -> int:
    """Register a new user and return their ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        return cursor.lastrowid
