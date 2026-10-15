from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from .config import get_settings


FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class WorkerPeerIdentity:
    fingerprint_sha256: str
    subject_sha256: str
    serial_sha256: str
    not_after: datetime


def _trusted_proxy(address: str | None, allowed: list[str]) -> bool:
    try:
        peer = ipaddress.ip_address(address or "")
    except ValueError:
        return False
    for value in allowed:
        try:
            if peer in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def _not_after(value: str) -> datetime:
    if len(value) > 128:
        raise ValueError("Worker certificate expiry header is oversized")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Worker certificate expiry header is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("Worker certificate expiry header requires an offset")
    parsed = parsed.astimezone(UTC)
    if parsed <= datetime.now(UTC):
        raise ValueError("Worker certificate has expired")
    return parsed


def worker_peer_identity(
    request: Request,
    verified: Annotated[
        str | None,
        Header(alias="X-iCheck-Client-Cert-Verified"),
    ] = None,
    fingerprint: Annotated[
        str | None,
        Header(alias="X-iCheck-Client-Cert-SHA256"),
    ] = None,
    subject: Annotated[
        str | None,
        Header(alias="X-iCheck-Client-Cert-Subject"),
    ] = None,
    serial: Annotated[
        str | None,
        Header(alias="X-iCheck-Client-Cert-Serial"),
    ] = None,
    not_after: Annotated[
        str | None,
        Header(alias="X-iCheck-Client-Cert-Not-After"),
    ] = None,
) -> WorkerPeerIdentity | None:
    settings = get_settings()
    values = (verified, fingerprint, subject, serial, not_after)
    supplied = any(value is not None for value in values)
    if settings.worker_mtls_mode == "disabled":
        if supplied:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Forwarded Worker certificate identity is disabled",
            )
        return None
    if not supplied:
        if settings.worker_mtls_mode == "required":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Verified Worker client certificate is required",
            )
        return None
    client_address = request.client.host if request.client is not None else None
    if not _trusted_proxy(
        client_address,
        settings.worker_mtls_trusted_proxy_list,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Worker certificate headers came from an untrusted proxy",
        )
    if any(value is None for value in values) or verified != "SUCCESS":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Worker certificate identity headers are incomplete or unverified",
        )
    assert fingerprint is not None
    assert subject is not None
    assert serial is not None
    assert not_after is not None
    normalized = fingerprint.replace(":", "").strip().lower()
    if FINGERPRINT_PATTERN.fullmatch(normalized) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Worker certificate SHA-256 fingerprint is invalid",
        )
    if not 1 <= len(subject.encode("utf-8")) <= 4096:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Worker certificate subject header is invalid",
        )
    if not 1 <= len(serial.encode("utf-8")) <= 256:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Worker certificate serial header is invalid",
        )
    try:
        expiry = _not_after(not_after)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
    return WorkerPeerIdentity(
        fingerprint_sha256=normalized,
        subject_sha256=hashlib.sha256(subject.encode("utf-8")).hexdigest(),
        serial_sha256=hashlib.sha256(serial.encode("utf-8")).hexdigest(),
        not_after=expiry,
    )

