import sqlite3
import os


DB_PATH = os.environ.get("DATABASE_PATH", "./taskflow.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER,
            filename TEXT NOT NULL,
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )
    """)
    conn.commit()
    conn.close()


def get_all_tasks():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_task(task_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_task(title, description=""):
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO tasks (title, description) VALUES (?, ?)",
        (title, description),
    )
    conn.commit()
    task_id = cursor.lastrowid
    conn.close()
    return task_id


def search_tasks(term):
    conn = get_connection()
    query = "SELECT * FROM tasks WHERE title LIKE '%" + term + "%' OR description LIKE '%" + term + "%'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_task(task_id, title=None, description=None, status=None):
    conn = get_connection()
    task = get_task(task_id)
    if not task:
        return None
    conn.execute(
        "UPDATE tasks SET title=?, description=?, status=? WHERE id=?",
        (
            title or task["title"],
            description or task["description"],
            status or task["status"],
            task_id,
        ),
    )
    conn.commit()
    conn.close()
    return get_task(task_id)


def delete_task(task_id):
    conn = get_connection()
    conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()
