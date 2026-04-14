"""
Token issuance and verification.
CWE-287: accepts 'none' algorithm — no signature validation.
CWE-327: HMAC-MD5 used for token signing.
"""
import base64
import json
import hmac
import hashlib
import time

# CWE-798: hardcoded signing secret
SIGNING_SECRET = "gateway-token-secret-2024"


def issue_token(username: str) -> str:
    """Issue a signed token for the given user."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + 3600}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    # CWE-327: HMAC with MD5 instead of SHA-256
    sig = hmac.new(SIGNING_SECRET.encode(), h + b"." + p, hashlib.md5).hexdigest()
    return f"{h.decode()}.{p.decode()}.{sig}"


def verify(token: str) -> dict:
    """Verify token — vulnerable to algorithm confusion attack."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"valid": False, "reason": "malformed"}
        h_raw, p_raw, sig = parts
        header = json.loads(base64.urlsafe_b64decode(h_raw + "=="))
        alg = header.get("alg", "HS256")

        # CWE-287: if alg == 'none', skip signature verification entirely
        if alg.lower() == "none":
            payload = json.loads(base64.urlsafe_b64decode(p_raw + "=="))
            return {"valid": True, "payload": payload, "warning": "no signature check"}

        payload = json.loads(base64.urlsafe_b64decode(p_raw + "=="))
        if payload.get("exp", 0) < time.time():
            return {"valid": False, "reason": "expired"}
        return {"valid": True, "payload": payload}
    except Exception as exc:
        return {"valid": False, "reason": str(exc)}
