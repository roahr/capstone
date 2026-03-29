"""
Test fixture: Vulnerable Python code samples for SEC-C testing.

Contains intentionally vulnerable code patterns for each CWE type
that the framework should detect.

WARNING: This code is intentionally insecure. Do NOT use in production.
"""

import os
import pickle
import sqlite3
import subprocess


# CWE-89: SQL Injection
def get_user_unsafe(username):
    """SQL injection via string formatting."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # VULNERABLE: unsanitized input in SQL
    return cursor.fetchall()


# CWE-89: SQL Injection (concatenation variant)
def search_products(search_term):
    """SQL injection via string concatenation."""
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")  # VULNERABLE
    return cursor.fetchall()


# CWE-78: OS Command Injection
def ping_host(hostname):
    """Command injection via os.system."""
    os.system(f"ping -c 1 {hostname}")  # VULNERABLE: unsanitized input in command


# CWE-78: OS Command Injection (subprocess variant)
def run_command(user_input):
    """Command injection via subprocess with shell=True."""
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True)  # VULNERABLE
    return result.stdout


# CWE-22: Path Traversal
def read_file(filename):
    """Path traversal via user-controlled file path."""
    filepath = os.path.join("/uploads", filename)
    with open(filepath) as f:  # VULNERABLE: no path validation
        return f.read()


# CWE-502: Deserialization of Untrusted Data
def load_user_data(data_bytes):
    """Unsafe deserialization of untrusted data."""
    return pickle.loads(data_bytes)  # VULNERABLE: pickle RCE


# CWE-79: Cross-site Scripting (Flask)
def render_greeting(name):
    """XSS via unescaped user input."""
    return f"<h1>Hello, {name}!</h1>"  # VULNERABLE: no HTML escaping


# CWE-95: Eval Injection
def calculate(expression):
    """Code injection via eval()."""
    return eval(expression)  # VULNERABLE: arbitrary code execution


# CWE-798: Hardcoded Credentials
DATABASE_PASSWORD = "super_secret_password_123"  # VULNERABLE: hardcoded secret
API_KEY = "sk-1234567890abcdef"  # VULNERABLE: hardcoded API key


# CWE-327: Broken Cryptographic Algorithm
def hash_password(password):
    """Weak hashing algorithm."""
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: MD5 is broken
