"""
Demo Case 2: GNN Stage Escalation (Stage 2)

Multi-step taint flows through helper functions. CodeQL tracks the taint
across 4+ function calls, producing taint_path_length > 3 which triggers
escalation to the Graph stage regardless of uncertainty score.

The GNN analyzes the code property graph and conformal prediction decides:
  - Singleton set {"vulnerable"} -> resolved at Stage 2
  - Ambiguous set {"safe","vulnerable"} -> escalated to Stage 3 (LLM)

Expected: Findings escalate past SAST to GNN (Stage 2).
"""
from flask import Flask, request
import sqlite3
import subprocess

app = Flask(__name__)


# === SQL Injection via multi-hop taint (CWE-89) ===

def get_search_term():
    """Hop 1: Source - user input enters the system."""
    return request.args.get("q", "")

def sanitize_input(raw_input):
    """Hop 2: Fake sanitizer - does nothing useful."""
    cleaned = raw_input.strip()
    return cleaned

def build_user_query(term):
    """Hop 3: Query construction - taint propagates into SQL."""
    return "SELECT name, email FROM users WHERE name LIKE '%" + term + "%'"

def run_database_query(query_string):
    """Hop 4: Sink - tainted query executed against database."""
    conn = sqlite3.connect("application.db")
    cursor = conn.cursor()
    cursor.execute(query_string)
    rows = cursor.fetchall()
    conn.close()
    return rows

@app.route("/search")
def search_users():
    """Entry point: 4-hop taint flow source -> sanitize -> build -> execute."""
    raw = get_search_term()
    cleaned = sanitize_input(raw)
    query = build_user_query(cleaned)
    results = run_database_query(query)
    return str(results)


# === Command Injection via multi-hop taint (CWE-78) ===

def read_config_value(key):
    """Hop 1: Source - reads from user-controlled request."""
    return request.form.get(key, "")

def format_command(binary, args):
    """Hop 2: Command assembly - taint enters shell command."""
    return f"{binary} {args}"

def execute_on_host(cmd):
    """Hop 3: Sink - tainted command executed on host."""
    return subprocess.check_output(cmd, shell=True)

@app.route("/deploy", methods=["POST"])
def deploy_service():
    """Entry point: 3-hop command injection taint flow."""
    service = read_config_value("service_name")
    cmd = format_command("/usr/bin/systemctl restart", service)
    output = execute_on_host(cmd)
    return output.decode()


# === Path Traversal via multi-hop taint (CWE-22) ===

def get_document_name():
    """Hop 1: Source - filename from user request."""
    return request.args.get("doc", "index.html")

def resolve_path(base_dir, filename):
    """Hop 2: Path construction without validation."""
    import os
    return os.path.join(base_dir, filename)

def read_document(full_path):
    """Hop 3: Sink - arbitrary file read."""
    with open(full_path, "r") as f:
        return f.read()

@app.route("/docs")
def serve_document():
    """Entry point: 3-hop path traversal."""
    name = get_document_name()
    path = resolve_path("/var/www/docs", name)
    content = read_document(path)
    return content
