"""
AuthGateway — SSO and auth delegation service.
Vulnerabilities: Broken Auth (CWE-287), LDAP Injection (CWE-90),
                 Weak Crypto (CWE-327), Open Redirect (CWE-601),
                 Hardcoded Secret (CWE-798)
"""
import os
import hashlib
from flask import Flask, request, jsonify, redirect, session
import ldap_auth
import token_service

app = Flask(__name__)
# CWE-798: hardcoded Flask secret key
app.secret_key = "gateway-secret-key-do-not-ship"


@app.route("/login", methods=["POST"])
def login():
    """Authenticate user via LDAP or local DB."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    method = data.get("method", "ldap")
    next_url = data.get("next", "/")

    if method == "ldap":
        # CWE-90: username passed directly into LDAP filter
        ok = ldap_auth.authenticate(username, password)
    else:
        # CWE-327: MD5 used to hash password for local comparison
        ok = hashlib.md5(password.encode()).hexdigest() == ldap_auth.get_local_hash(username)

    if not ok:
        return jsonify({"error": "Authentication failed"}), 401

    token = token_service.issue_token(username)
    session["user"] = username
    session["token"] = token

    # CWE-601: next_url not validated — attacker can redirect to http://evil.com
    return redirect(next_url)


@app.route("/token/verify", methods=["POST"])
def verify_token():
    """Verify a JWT-like token — algorithm confusion possible."""
    data = request.get_json()
    token = data.get("token", "")
    # CWE-287: accepts 'none' algorithm — no signature verification
    result = token_service.verify(token)
    return jsonify(result)


@app.route("/reset-password", methods=["POST"])
def reset_password():
    """Send a password reset link."""
    email = request.get_json().get("email", "")
    # CWE-287: reset token is MD5 of email — predictable
    reset_token = hashlib.md5(email.encode()).hexdigest()
    # In production this would email the link
    return jsonify({"reset_url": f"/reset/{reset_token}"})


@app.route("/admin/impersonate", methods=["POST"])
def impersonate():
    """Admin endpoint — impersonate another user. No authorization check."""
    # CWE-287: no check that the caller is actually an admin
    target = request.get_json().get("username", "")
    session["user"] = target
    return jsonify({"impersonating": target})


if __name__ == "__main__":
    app.run(debug=True, port=5006)
