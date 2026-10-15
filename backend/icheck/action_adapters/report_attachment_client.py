"""Adapter-side retrieval of approved report bytes from a configured iCheck host."""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

import httpx

from ..report_schemas import ReportAttachmentManifest


class ReportAttachmentClient:
    def __init__(
        self, base_url: str, *, access_token: str, tenant_id: str, region_id: str,
        timeout_seconds: float = 30, transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
            raise ValueError("Attachment retrieval requires a configured HTTPS origin without credentials or a path")
        if not access_token or not tenant_id or not region_id or not 0 < timeout_seconds <= 120:
            raise ValueError("Attachment retrieval identity and bounded timeout are required")
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), follow_redirects=False, trust_env=False,
            timeout=timeout_seconds, transport=transport,
            headers={"Authorization": f"Bearer {access_token}",
                     "X-Icheck-Tenant-ID": tenant_id, "X-Icheck-Region-ID": region_id,
                     "Accept-Encoding": "identity"},
        )

    def close(self) -> None:
        self._client.close()

    def fetch(self, manifest: ReportAttachmentManifest | dict) -> bytes:
        expected = ReportAttachmentManifest.model_validate(manifest)
        with self._client.stream("GET", f"/api/v1/reports/attachments/{expected.attachment_id}/content") as response:
            if response.status_code != 200:
                raise ValueError(f"Report attachment retrieval failed with HTTP {response.status_code}")
            checks = {
                "X-Icheck-Snapshot-SHA256": expected.snapshot_sha256,
                "X-Icheck-Content-SHA256": expected.document_sha256,
                "X-Icheck-Artifact-Version-ID": expected.artifact_version_id,
                "X-Icheck-Renderer": expected.renderer,
            }
            if (any(response.headers.get(key) != value for key, value in checks.items())
                or response.headers.get("Content-Type", "").split(";", 1)[0] != expected.media_type):
                raise ValueError("Report attachment response does not match its approved manifest")
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=64_000):
                if len(body) + len(chunk) > expected.size_bytes:
                    raise ValueError("Report attachment exceeds its approved size")
                body.extend(chunk)
            if len(body) != expected.size_bytes or hashlib.sha256(body).hexdigest() != expected.document_sha256:
                raise ValueError("Report attachment bytes do not match their approved digest")
            return bytes(body)

    def __enter__(self) -> ReportAttachmentClient:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
