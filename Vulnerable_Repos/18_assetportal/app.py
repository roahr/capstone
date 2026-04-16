"""
AssetPortal — internal file management portal.
Vulnerabilities: Unrestricted Upload (CWE-434), Path Traversal (CWE-22),
                 Weak Crypto (CWE-327), Hardcoded Secret (CWE-798)
"""
import os
import hashlib
from flask import Flask, request, jsonify, send_file
import storage
import crypto

app = Flask(__name__)
# CWE-798: hardcoded admin token
ADMIN_TOKEN = "assetportal-admin-2024-secret"
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")


def require_auth(req):
    return req.headers.get("Authorization") == f"Bearer {ADMIN_TOKEN}"


@app.route("/assets/upload", methods=["POST"])
def upload_asset():
    """Upload a file asset — no extension or content validation."""
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    # CWE-434: no restriction on file type, extension, or content
    # attacker can upload .php, .py, .sh, .exe etc.
    filename = f.filename
    # CWE-22: filename not sanitized — can include ../../../etc/passwd
    path = storage.save_file(filename, f.read())
    checksum = crypto.checksum(f.read() if f.read() else b"")
    return jsonify({"path": path, "checksum": checksum}), 201


@app.route("/assets/<path:filename>", methods=["GET"])
def download_asset(filename):
    """Download an asset by filename."""
    # CWE-22: path traversal — filename not constrained to UPLOAD_DIR
    full_path = storage.resolve_path(filename)
    return send_file(full_path)


@app.route("/assets/<path:filename>/verify", methods=["GET"])
def verify_asset(filename):
    """Verify asset integrity via MD5 checksum."""
    full_path = storage.resolve_path(filename)
    with open(full_path, "rb") as fh:
        data = fh.read()
    # CWE-327: MD5 used for integrity verification
    checksum = crypto.checksum(data)
    stored = storage.get_checksum(filename)
    return jsonify({"match": checksum == stored, "algo": "md5"})


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    app.run(debug=True, port=5005)
