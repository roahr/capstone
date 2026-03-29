"""
SecureNotes — Authentication Module

Provides JWT-based authentication for the Flask API:
  - Password hashing with bcrypt
  - Token generation and verification
  - Login / registration helpers
"""

import os
import hmac
import hashlib
import secrets
import time
from functools import wraps
from typing import Optional

from flask import request, jsonify, g

import db


# ---------------------------------------------------------------------------
# TRUE POSITIVE: CWE-798 Hardcoded Credentials
# Production database password and API key are embedded directly in source.
# These should be loaded exclusively from environment variables or a vault.
# ---------------------------------------------------------------------------
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-prod-a1b2c3d4e5f6"

JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
TOKEN_EXPIRY = 3600  # seconds


# ---------------------------------------------------------------------------
# FALSE POSITIVE #12: CWE-798 — Default immediately overwritten
# (Adversarial tier, LLM resolves)
# `user_password` is initialised to a placeholder string, but is
# unconditionally replaced by the environment variable lookup on the very
# next line.  A shallow string-literal scan flags this, but the value never
# reaches any credential check.
# ---------------------------------------------------------------------------
def get_db_credentials() -> dict:
    """Build a credentials dict for the database connection.

    The placeholder defaults are overridden by environment variables so that
    the app can start in development mode without .env, yet production
    always uses injected secrets.
    """
    user_password = "placeholder"
    user_password = os.environ.get("DB_PASS", user_password)

    db_user = "app_user"
    db_user = os.environ.get("DB_USER", db_user)

    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", "5432")),
        "user": db_user,
        "password": user_password,
    }


# ---- Password hashing (HMAC-SHA256 with per-user salt) -------------------

def hash_password(password: str) -> str:
    """Return a salted HMAC-SHA256 hash of `password`."""
    salt = secrets.token_hex(16)
    digest = hmac.new(
        salt.encode(), password.encode(), hashlib.sha256
    ).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Check `password` against a previously stored hash."""
    try:
        salt, digest = stored_hash.split("$", 1)
    except ValueError:
        return False
    expected = hmac.new(
        salt.encode(), password.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, digest)


# ---- Minimal JWT-like token implementation --------------------------------

def _base64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_token(user_id: int, username: str) -> str:
    """Create an HMAC-signed bearer token encoding `user_id` and expiry."""
    payload = f"{user_id}:{username}:{int(time.time()) + TOKEN_EXPIRY}"
    signature = hmac.new(
        JWT_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


def verify_token(token: str) -> Optional[dict]:
    """Validate and decode a bearer token.

    Returns a dict with `user_id` and `username`, or None on failure.
    """
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(
            JWT_SECRET.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        user_id_str, username, expiry_str = payload.split(":")
        if int(expiry_str) < time.time():
            return None
        return {"user_id": int(user_id_str), "username": username}
    except (ValueError, AttributeError):
        return None


# ---- Flask decorator for protected routes ---------------------------------

def login_required(f):
    """Decorator that rejects unauthenticated requests with 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1]
        claims = verify_token(token)
        if claims is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.current_user = claims
        return f(*args, **kwargs)
    return decorated


# ---- High-level auth helpers used by routes -------------------------------

def register_user(username: str, password: str, email: str = "") -> dict:
    """Register a new user and return a bearer token."""
    existing = db.get_user_by_username(username)
    if existing:
        return {"error": "Username already taken"}, 409

    pw_hash = hash_password(password)
    user_id = db.create_user(username, pw_hash, email)
    token = generate_token(user_id, username)
    return {"token": token, "user_id": user_id}


def login_user(username: str, password: str) -> dict:
    """Authenticate an existing user and return a bearer token."""
    user = db.get_user_by_username(username)
    if user is None or not verify_password(password, user["password_hash"]):
        return {"error": "Invalid credentials"}, 401

    token = generate_token(user["id"], user["username"])
    return {"token": token, "user_id": user["id"]}
