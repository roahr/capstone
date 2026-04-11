import os
import sqlite3
import time
from pathlib import Path


STORAGE_DIR = os.environ.get("DOCVAULT_STORAGE", "./vault")
DB_PATH = os.path.join(STORAGE_DIR, "metadata.db")


def _ensure_storage():
    Path(STORAGE_DIR).mkdir(parents=True, exist_ok=True)


def _get_db():
    _ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS documents ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  filename TEXT NOT NULL,"
        "  content_type TEXT,"
        "  size INTEGER,"
        "  uploaded_at REAL"
        ")"
    )
    conn.commit()
    return conn


def save_file(filename, data, content_type="application/octet-stream"):
    _ensure_storage()
    filepath = os.path.join(STORAGE_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(data)

    db = _get_db()
    db.execute(
        "INSERT INTO documents (filename, content_type, size, uploaded_at) VALUES (?, ?, ?, ?)",
        (filename, content_type, len(data), time.time()),
    )
    db.commit()
    db.close()
    return filepath


def read_file(filename):
    filepath = os.path.join(STORAGE_DIR, filename)
    if not os.path.isfile(filepath):
        return None
    with open(filepath, "rb") as f:
        return f.read()


def list_files():
    db = _get_db()
    rows = db.execute(
        "SELECT filename, content_type, size, uploaded_at FROM documents ORDER BY uploaded_at DESC"
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def remove_file(filename):
    filepath = os.path.join(STORAGE_DIR, filename)
    if os.path.isfile(filepath):
        os.remove(filepath)
    db = _get_db()
    db.execute("DELETE FROM documents WHERE filename = ?", (filename,))
    db.commit()
    db.close()
