"""
Demo Case 3: LLM Stage Escalation (Stage 3)

These vulnerabilities are subtle and ambiguous -- the GNN may produce
ambiguous conformal prediction sets {"safe", "vulnerable"}, which triggers
escalation to the LLM dual-agent stage (Attacker + Defender consensus).

The LLM stage:
  - Attacker agent: constructs exploit scenarios
  - Defender agent: identifies sanitizers/mitigations
  - Consensus: CVSS v3.1 scoring + final verdict

Expected: Some findings escalate through GNN to LLM for dual-agent analysis.
"""
from flask import Flask, request, render_template, jsonify
import hashlib
import hmac
import os
import re

app = Flask(__name__)
SECRET_KEY = os.environ.get("APP_SECRET", "default-secret-key-change-me")


# === CWE-352: Cross-Site Request Forgery (subtle, no clear pattern) ===

@app.route("/transfer", methods=["POST"])
def transfer_funds():
    """
    Processes a fund transfer. Has CSRF token check but the validation
    is flawed -- accepts any token that starts with the right prefix.
    A GNN might be uncertain whether this is safe or vulnerable.
    """
    csrf_token = request.form.get("csrf_token", "")
    if not csrf_token.startswith("sec_"):
        return "Invalid token", 403

    # Token "validated" but never actually checked against session
    amount = float(request.form.get("amount", 0))
    to_account = request.form.get("to", "")

    # Process transfer (no actual CSRF protection)
    return jsonify({"status": "transferred", "amount": amount, "to": to_account})


# === CWE-327: Broken Cryptography (context-dependent) ===

def generate_token(user_id, timestamp):
    """
    Uses MD5 for token generation. MD5 is cryptographically broken for
    collision resistance but still provides preimage resistance for
    short-lived tokens. Whether this is a real vulnerability depends
    on the threat model -- ambiguous for automated tools.
    """
    payload = f"{user_id}:{timestamp}:{SECRET_KEY}"
    return hashlib.md5(payload.encode()).hexdigest()

def verify_token(token, user_id, timestamp, window=300):
    expected = generate_token(user_id, timestamp)
    return hmac.compare_const(expected, token)


# === CWE-918: Server-Side Request Forgery (partial mitigation) ===

ALLOWED_HOSTS = ["api.internal.com", "cdn.internal.com"]

def fetch_resource(url):
    """
    Has an allowlist but the check is bypassable via URL encoding
    or DNS rebinding. Partially mitigated but not fully safe.
    """
    import urllib.parse
    parsed = urllib.parse.urlparse(url)

    # Allowlist check (bypassable)
    if parsed.hostname not in ALLOWED_HOSTS:
        return None

    import urllib.request
    return urllib.request.urlopen(url).read()

@app.route("/proxy")
def proxy_request():
    target_url = request.args.get("url", "")
    if not target_url:
        return "Missing url parameter", 400

    data = fetch_resource(target_url)
    if data is None:
        return "Blocked by allowlist", 403
    return data


# === CWE-209: Information Exposure Through Error Messages ===

@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    """
    Error handling exposes internal details. Whether this is exploitable
    depends on what information the stack trace reveals.
    """
    try:
        import sqlite3
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": f"User {user_id} not found in database users.db"}), 404
        return jsonify({"user": user})
    except Exception as e:
        # Leaks internal error details including file paths and SQL structure
        return jsonify({
            "error": str(e),
            "traceback": repr(e.__traceback__),
            "database": "users.db",
            "query": f"SELECT * FROM users WHERE id = {user_id}"
        }), 500
