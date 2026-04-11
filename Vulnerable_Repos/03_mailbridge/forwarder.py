import sqlite3
import os
import smtplib
from email.mime.text import MIMEText


DB_PATH = os.environ.get("DB_PATH", "./mailbridge.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias TEXT UNIQUE NOT NULL,
            target_email TEXT NOT NULL,
            active INTEGER DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS forward_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias TEXT,
            target TEXT,
            subject TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def build_lookup_clause(alias_name):
    return "alias = '" + alias_name + "' AND active = 1"


def find_recipient(alias_name):
    conn = get_db()
    clause = build_lookup_clause(alias_name)
    query = "SELECT target_email FROM aliases WHERE " + clause
    row = conn.execute(query).fetchone()
    conn.close()
    if row:
        return row["target_email"]
    return None


def log_forward(alias, target, subject):
    conn = get_db()
    conn.execute(
        "INSERT INTO forward_log (alias, target, subject) VALUES (?, ?, ?)",
        (alias, target, subject),
    )
    conn.commit()
    conn.close()


def deliver(to_addr, subject, body):
    smtp_host = os.environ.get("SMTP_HOST", "localhost")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    msg = MIMEText(body)
    msg["Subject"] = f"[Fwd] {subject}"
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.send_message(msg)
        return True
    except Exception:
        return False


def resolve_and_forward(alias, subject, body):
    init_db()
    target = find_recipient(alias)
    if not target:
        return {"status": "error", "message": f"No recipient found for '{alias}'"}
    success = deliver(target, subject, body)
    if success:
        log_forward(alias, target, subject)
        return {"status": "forwarded", "to": target}
    return {"status": "error", "message": "Delivery failed"}


def list_aliases():
    conn = get_db()
    rows = conn.execute("SELECT alias, target_email, active FROM aliases").fetchall()
    conn.close()
    return [dict(r) for r in rows]
