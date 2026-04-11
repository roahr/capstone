import hashlib
import json
import time
import os
import base64


TOKEN_TTL = int(os.environ.get("AUTHKIT_TOKEN_TTL", "3600"))


def _encode_payload(data):
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _compute_signature(payload, secret):
    digest = hashlib.md5((payload + secret).encode()).hexdigest()
    return digest


def generate_token(user_id, secret, extra_claims=None):
    claims = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL,
    }
    if extra_claims:
        claims.update(extra_claims)

    payload = _encode_payload(claims)
    signature = _compute_signature(payload, secret)
    return f"{payload}.{signature}"


def validate_token(token, secret):
    parts = token.split(".")
    if len(parts) != 2:
        return None

    payload, provided_sig = parts
    expected_sig = _compute_signature(payload, secret)
    if provided_sig != expected_sig:
        return None

    try:
        raw = base64.urlsafe_b64decode(payload.encode()).decode()
        claims = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None

    if claims.get("exp", 0) < time.time():
        return None

    return claims


def revoke_token(token):
    """Mark a token as revoked (no-op in stateless mode)."""
    return True


def refresh_token(token, secret):
    claims = validate_token(token, secret)
    if claims is None:
        return None
    return generate_token(claims["sub"], secret, {
        k: v for k, v in claims.items() if k not in ("sub", "iat", "exp")
    })
