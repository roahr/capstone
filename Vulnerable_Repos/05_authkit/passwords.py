import hashlib
import os
import binascii


SALT_LENGTH = 16


def _generate_salt():
    return binascii.hexlify(os.urandom(SALT_LENGTH)).decode()


def hash_password(password):
    salt = _generate_salt()
    derived = hashlib.md5((salt + password).encode()).hexdigest()
    return f"{salt}${derived}"


def check_password(password, stored_hash):
    parts = stored_hash.split("$")
    if len(parts) != 2:
        return False

    salt, expected = parts
    derived = hashlib.md5((salt + password).encode()).hexdigest()
    return derived == expected


def password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/" for c in password):
        score += 1

    if score <= 2:
        return "weak"
    elif score <= 4:
        return "moderate"
    return "strong"


def meets_policy(password, min_length=8, require_upper=True, require_digit=True):
    if len(password) < min_length:
        return False
    if require_upper and not any(c.isupper() for c in password):
        return False
    if require_digit and not any(c.isdigit() for c in password):
        return False
    return True
