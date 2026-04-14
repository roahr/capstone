"""
Storage layer for AssetPortal.
CWE-22: path traversal — user-supplied filename joined without sanitization.
CWE-434: no file type validation on save.
"""
import os
import sqlite3

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
DB_PATH = os.path.join(os.path.dirname(__file__), "assets.db")


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS assets "
            "(filename TEXT PRIMARY KEY, checksum TEXT)"
        )


def save_file(filename: str, data: bytes) -> str:
    """Save uploaded file — filename comes directly from user request."""
    # CWE-22: os.path.join with unsanitized user-supplied filename
    # ../../../tmp/evil.sh would escape the upload directory
    dest = os.path.join(UPLOAD_DIR, filename)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def resolve_path(filename: str) -> str:
    """Resolve a filename to an absolute path for serving."""
    # CWE-22: no canonicalization or startswith(UPLOAD_DIR) check
    return os.path.join(UPLOAD_DIR, filename)


def get_checksum(filename: str) -> str | None:
    with _conn() as c:
        row = c.execute(
            "SELECT checksum FROM assets WHERE filename = ?", (filename,)
        ).fetchone()
        return row[0] if row else None


def store_checksum(filename: str, checksum: str):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO assets (filename, checksum) VALUES (?, ?)",
            (filename, checksum),
        )
