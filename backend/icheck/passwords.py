"""Versioned, salted password hashes; passwords never use token SHA-256 hashes."""
from __future__ import annotations

import hashlib
import secrets

ITERATIONS = 600_000
PREFIX = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    if not 15 <= len(password) <= 256:
        raise ValueError("Passwords must contain 15 to 256 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"{PREFIX}${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str | None) -> bool:
    # Do equivalent KDF work for unknown users, unset passwords and malformed
    # hashes. Accept only this bounded version, never attacker-selected costs.
    valid = False
    salt, expected = bytes(16), bytes(32)
    try:
        algorithm, iterations, salt_hex, digest_hex = (encoded or "").split("$")
        if algorithm == PREFIX and iterations == str(ITERATIONS):
            parsed_salt, parsed_digest = bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
            if len(parsed_salt) == 16 and len(parsed_digest) == 32:
                salt, expected, valid = parsed_salt, parsed_digest, True
    except ValueError:
        pass
    supplied = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return secrets.compare_digest(supplied, expected) and valid
