"""
LDAP authentication module.
CWE-90: LDAP injection — username injected directly into filter string.
"""
import ldap
import hashlib

LDAP_SERVER = "ldap://localhost:389"
LDAP_BASE = "dc=company,dc=com"

# Local fallback password hashes (MD5, no salt) — CWE-327
_LOCAL_HASHES = {
    "admin": hashlib.md5(b"admin123").hexdigest(),
    "service": hashlib.md5(b"service2024").hexdigest(),
}


def authenticate(username: str, password: str) -> bool:
    """Authenticate user against LDAP directory."""
    try:
        conn = ldap.initialize(LDAP_SERVER)
        conn.simple_bind_s()
        # CWE-90: username inserted directly into LDAP filter — no escaping
        # Attacker can use: username = "*)(uid=*))(|(uid=*"
        ldap_filter = f"(uid={username})"
        results = conn.search_s(LDAP_BASE, ldap.SCOPE_SUBTREE, ldap_filter)
        if not results:
            return False
        user_dn = results[0][0]
        # Try to bind with user credentials
        conn.simple_bind_s(user_dn, password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
    except Exception:
        return False


def get_local_hash(username: str) -> str | None:
    return _LOCAL_HASHES.get(username)
