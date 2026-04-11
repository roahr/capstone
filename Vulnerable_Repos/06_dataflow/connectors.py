import sqlite3
import os


class SQLiteConnector:
    def __init__(self, db_path):
        self.db_path = db_path
        self._conn = None

    def connect(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        return self

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def fetch_all(self, query, params=None):
        cursor = self._conn.execute(query, params or ())
        return [dict(row) for row in cursor.fetchall()]

    def insert_rows(self, table, rows):
        if not rows:
            return 0
        columns = rows[0].keys()
        placeholders = ", ".join("?" for _ in columns)
        col_names = ", ".join(columns)
        stmt = f"INSERT INTO {table} ({col_names}) VALUES ({placeholders})"
        for row in rows:
            self._conn.execute(stmt, tuple(row[c] for c in columns))
        self._conn.commit()
        return len(rows)

    def execute_query(self, table, filters):
        where_parts = []
        for col, val in filters.items():
            where_parts.append("{} = '{}'".format(col, val))

        query = "SELECT * FROM " + table
        if where_parts:
            query += " WHERE " + " AND ".join(where_parts)

        cursor = self._conn.execute(query)
        return [dict(row) for row in cursor.fetchall()]

    def table_exists(self, table_name):
        result = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        return result is not None

    def row_count(self, table):
        cursor = self._conn.execute(f"SELECT COUNT(*) FROM {table}")
        return cursor.fetchone()[0]
