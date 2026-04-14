"""
Registry: stores webhook registrations in SQLite.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "webhooks.db")


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, url TEXT, secret TEXT
        )""")


def save_webhook(name: str, url: str, secret: str) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO webhooks (name, url, secret) VALUES (?, ?, ?)",
            (name, url, secret),
        )
        return cur.lastrowid


def get_webhook(wid: int) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT id, name, url, secret FROM webhooks WHERE id = ?", (wid,)
        ).fetchone()
        if row:
            return {"id": row[0], "name": row[1], "url": row[2], "secret": row[3]}
    return None
