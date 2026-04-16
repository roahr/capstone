"""
Cryptographic utilities.
CWE-327: MD5 used for file integrity — weak, collision-prone.
"""
import hashlib


def checksum(data: bytes) -> str:
    """Compute MD5 checksum of data. Used for file integrity verification."""
    # CWE-327: MD5 is cryptographically broken — use SHA-256 for integrity
    return hashlib.md5(data).hexdigest()


def hash_password(password: str) -> str:
    """Hash a user password for storage."""
    # CWE-327: MD5 without salt — trivially reversible via rainbow table
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash
