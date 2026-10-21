"""Reuse installed key custody, with connection-specific authenticated encryption."""
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class IntegrationCustodyUnavailable(ValueError):
    pass


def key():
    # Existing native installations already provision this API-owned protected key.
    # No new key file is generated and no AI provider is contacted.
    from .services.openrouter_setup import _key, ManagedAIUnavailable
    try:
        return _key()
    except ManagedAIUnavailable:
        raise IntegrationCustodyUnavailable("Protected integration key storage is unavailable") from None


def aad(row):
    # Provider and endpoint are immutable; moving a token to another origin needs
    # a new explicit connection. Revision is an execution guard, not key material.
    return json.dumps(["icheck.monitoring-integration-token/v1", row.id, row.tenant_id,
                       row.region_id, row.provider, row.api_url], separators=(",", ":")).encode()


def encrypt_token(row, token):
    nonce = os.urandom(12)
    return b"\x01" + nonce + AESGCM(key()).encrypt(nonce, token.encode("ascii"), aad(row))


def decrypt_token(row):
    try:
        raw = row.encrypted_token
        if raw[:1] != b"\x01":
            raise ValueError()
        return AESGCM(key()).decrypt(raw[1:13], raw[13:], aad(row)).decode("ascii")
    except Exception:
        raise IntegrationCustodyUnavailable("Integration token custody is unavailable or has changed") from None
