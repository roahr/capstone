"""
SecureNotes — Utility Functions

Miscellaneous helpers used across the application:
  - Note export / backup
  - Session serialization
  - Safe math evaluation for computed fields
"""

import os
import re
import base64
import pickle
import subprocess
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

BACKUP_DIR = os.environ.get("SECURENOTES_BACKUP_DIR", "/var/backups/securenotes")
DATA_DIR = os.environ.get("SECURENOTES_DATA_DIR", "/tmp/notes")


# ---------------------------------------------------------------------------
# TRUE POSITIVE: CWE-78 OS Command Injection
# `filename` is user-supplied and concatenated straight into a shell command
# via os.system().  An attacker can inject arbitrary commands with
# characters like ; or $(...).
# ---------------------------------------------------------------------------
def export_notes(filename: str) -> bool:
    """Export all notes to a compressed tarball.

    Args:
        filename: Base name for the archive (without extension).

    Returns:
        True on success, False otherwise.
    """
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        archive_path = os.path.join(BACKUP_DIR, filename)
        exit_code = os.system(f"tar -czf {archive_path}.tar.gz {DATA_DIR}")
        return exit_code == 0
    except OSError as exc:
        logger.error("Export failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# FALSE POSITIVE #8: CWE-78 — subprocess with list args, no shell
# (Basic tier, SAST resolves)
# Using the list form of subprocess.run avoids shell interpretation entirely.
# SAST tools that simply flag "subprocess" calls would raise a false alarm.
# ---------------------------------------------------------------------------
def create_backup() -> str:
    """Create a timestamped backup archive of the notes data directory.

    Returns:
        Path to the created backup file.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"backup_{timestamp}.tar.gz")
    data_dir = DATA_DIR

    os.makedirs(BACKUP_DIR, exist_ok=True)
    result = subprocess.run(
        ["tar", "-czf", backup_path, data_dir],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        logger.warning("Backup stderr: %s", result.stderr)
    return backup_path


# ---------------------------------------------------------------------------
# TRUE POSITIVE: CWE-502 Insecure Deserialization
# `pickle.loads` on user-controlled data can execute arbitrary code.
# An attacker who crafts a malicious pickle payload can achieve RCE.
# ---------------------------------------------------------------------------
def load_session(data: str) -> dict:
    """Restore a session object from a base64-encoded pickle string.

    Args:
        data: Base64-encoded, pickled session dict.

    Returns:
        The deserialised session dictionary.
    """
    try:
        raw = base64.b64decode(data)
        session_data = pickle.loads(raw)
        return session_data
    except Exception as exc:
        logger.error("Session decode failed: %s", exc)
        return {}


def save_session(session_dict: dict) -> str:
    """Serialise a session dictionary to a base64-encoded pickle string."""
    raw = pickle.dumps(session_dict)
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# FALSE POSITIVE #11: CWE-94 — eval() with strict allowlist
# (Adversarial tier, LLM resolves)
# The regex only permits digits, arithmetic operators, parentheses, dots,
# and whitespace.  No identifiers, builtins, or dunder methods can pass
# the filter, so code injection is not possible despite the use of eval().
# ---------------------------------------------------------------------------
def calculate_expression(expr: str) -> float:
    """Safely evaluate a simple arithmetic expression.

    Only numeric characters and basic math operators (+, -, *, /, ., ())
    are allowed.  Everything else is rejected before eval() is called.

    Args:
        expr: A string like "3.14 * (2 + 5)".

    Returns:
        The numeric result.

    Raises:
        ValueError: If the expression contains disallowed characters.
    """
    sanitized = expr.strip()
    if not re.match(r"^[0-9+\-*/().  ]+$", sanitized):
        raise ValueError(f"Invalid expression: {expr!r}")
    return float(eval(sanitized))


def format_timestamp(dt: datetime) -> str:
    """Return an ISO-8601 formatted string for the given datetime."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_html(text: str) -> str:
    """Escape HTML special characters to prevent XSS."""
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
    }
    for char, entity in replacements.items():
        text = text.replace(char, entity)
    return text
