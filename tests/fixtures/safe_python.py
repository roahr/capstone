"""
Test fixture: Safe Python code samples for SEC-C testing.

Contains properly secured code patterns that should NOT trigger
vulnerability alerts (true negatives).
"""

import hashlib
import os
import sqlite3
import subprocess


# Safe: Parameterized SQL query
def get_user_safe(username):
    """Parameterized query prevents SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


# Safe: ORM usage
def search_products_safe(search_term):
    """ORM handles parameterization."""
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM products WHERE name LIKE ?",
        (f"%{search_term}%",),
    )
    return cursor.fetchall()


# Safe: Subprocess with list args (no shell)
def ping_host_safe(hostname):
    """Safe subprocess call without shell=True."""
    # Validate hostname format
    import re
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname")
    subprocess.run(["ping", "-c", "1", hostname], capture_output=True)


# Safe: Path traversal prevention
def read_file_safe(filename):
    """Path traversal prevented by path validation."""
    base_dir = os.path.realpath("/uploads")
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    # Ensure the resolved path is within the base directory
    if not filepath.startswith(base_dir):
        raise ValueError("Path traversal detected")
    with open(filepath) as f:
        return f.read()


# Safe: JSON deserialization instead of pickle
def load_user_data_safe(data_string):
    """Safe deserialization using JSON."""
    import json
    return json.loads(data_string)


# Safe: HTML escaping
def render_greeting_safe(name):
    """XSS prevented by HTML escaping."""
    import html
    escaped = html.escape(name)
    return f"<h1>Hello, {escaped}!</h1>"


# Safe: No eval - use ast.literal_eval for safe expressions
def calculate_safe(expression):
    """Safe expression evaluation."""
    import ast
    return ast.literal_eval(expression)


# Safe: Environment variable for secrets
def get_database_password():
    """Credentials from environment, not hardcoded."""
    return os.environ.get("DATABASE_PASSWORD")


# Safe: Strong hashing
def hash_password_safe(password):
    """Strong password hashing with salt."""
    salt = os.urandom(32)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
