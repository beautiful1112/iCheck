from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from .collectors import (
    collect_http_json,
    collect_psrp_cim,
    collect_snmp_exporter,
    collect_windows_exporter,
)


class ControlPlaneClient:
    def __init__(self, base_url: str, timeout_seconds: int = 30):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout_seconds = timeout_seconds
        self.access_token: str | None = None

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "iCheck-collector/0.3",
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if extra_headers:
            headers.update(extra_headers)
        request = Request(
            urljoin(self.base_url, path.lstrip("/")),
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Control plane returned HTTP {exc.code}: {detail}"
            ) from exc
        if not response_body:
            return None
        return json.loads(response_body.decode("utf-8"))


ADAPTERS = {
    "http_json": collect_http_json,
    "psrp_cim": collect_psrp_cim,
    "snmp_exporter": collect_snmp_exporter,
    "windows_exporter": collect_windows_exporter,
}


def run_assignment(
    client: ControlPlaneClient,
    assignment: dict[str, Any],
    *,
    http_allowed_hosts: list[str],
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    windows_exporter_allowed_hosts: list[str],
    windows_allowed_targets: list[str],
    psrp_cim_executor: Any | None = None,
) -> bool:
    run_id = assignment["run_id"]
    lease_token = assignment["lease_token"]
    adapter_type = assignment["adapter_type"]
    try:
        assignment["_runtime"] = {
            "http_allowed_hosts": http_allowed_hosts,
            "exporter_allowed_hosts": exporter_allowed_hosts,
            "snmp_allowed_targets": snmp_allowed_targets,
            "windows_exporter_allowed_hosts": windows_exporter_allowed_hosts,
            "windows_allowed_targets": windows_allowed_targets,
            "psrp_cim_executor": psrp_cim_executor,
            "lease_seconds": assignment.get("_lease_seconds", 60),
        }
        adapter = ADAPTERS[adapter_type]
        envelopes = adapter(assignment)
        if envelopes:
            client.request(
                "POST",
                f"/api/v1/collector-runs/{run_id}/envelopes",
                {"lease_token": lease_token, "envelopes": envelopes},
            )
        client.request(
            "POST",
            f"/api/v1/collector-runs/{run_id}/complete",
            {
                "lease_token": lease_token,
                "status": "succeeded",
                "stats": {"adapter": adapter_type, "records": len(envelopes)},
            },
        )
        return True
    except Exception as exc:
        try:
            client.request(
                "POST",
                f"/api/v1/collector-runs/{run_id}/complete",
                {
                    "lease_token": lease_token,
                    "status": "failed",
                    "error": str(exc)[:10000],
                    "stats": {"adapter": adapter_type},
                },
            )
        except Exception as completion_exc:
            print(
                f"failed to report run {run_id}: {completion_exc}",
                file=sys.stderr,
            )
        print(f"collector run {run_id} failed: {exc}", file=sys.stderr)
        return False


def run_once(
    client: ControlPlaneClient,
    worker_id: str,
    *,
    max_assignments: int,
    lease_seconds: int,
    http_allowed_hosts: list[str],
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    windows_exporter_allowed_hosts: list[str],
    windows_allowed_targets: list[str],
    psrp_cim_executor: Any | None = None,
) -> tuple[int, int]:
    client.request(
        "POST",
        f"/api/v1/collector-workers/{worker_id}/heartbeat",
        {"state": "online"},
    )
    assignments = client.request(
        "POST",
        f"/api/v1/collector-workers/{worker_id}/leases/claim",
        {
            "max_assignments": max_assignments,
            "lease_seconds": lease_seconds,
        },
    )
    for item in assignments:
        item["_lease_seconds"] = lease_seconds
    with ThreadPoolExecutor(max_workers=max(1, len(assignments))) as executor:
        outcomes = list(
            executor.map(
                lambda item: run_assignment(
                    client,
                    item,
                    http_allowed_hosts=http_allowed_hosts,
                    exporter_allowed_hosts=exporter_allowed_hosts,
                    snmp_allowed_targets=snmp_allowed_targets,
                    windows_exporter_allowed_hosts=(
                        windows_exporter_allowed_hosts
                    ),
                    windows_allowed_targets=windows_allowed_targets,
                    psrp_cim_executor=psrp_cim_executor,
                ),
                assignments,
            )
        )
    succeeded = sum(outcomes)
    return succeeded, len(assignments) - succeeded


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an iCheck collector worker")
    parser.add_argument(
        "--control-plane",
        default=os.getenv("ICHECK_CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--name",
        default=os.getenv("ICHECK_COLLECTOR_NAME", socket.gethostname()),
    )
    parser.add_argument("--site", default=os.getenv("ICHECK_COLLECTOR_SITE"))
    parser.add_argument(
        "--capability",
        action="append",
        dest="capabilities",
        default=None,
        help="Adapter type supported by this worker; may be repeated",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_POLL_SECONDS", "5")),
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_LEASE_SECONDS", "60")),
    )
    parser.add_argument(
        "--max-assignments",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_MAX_ASSIGNMENTS", "1")),
    )
    parser.add_argument(
        "--http-allowed-host",
        action="append",
        dest="http_allowed_hosts",
        default=None,
        help="Exact hostname or *.suffix allowed for HTTP collection",
    )
    parser.add_argument(
        "--registration-token-file",
        default=os.getenv("ICHECK_COLLECTOR_REGISTRATION_TOKEN_FILE"),
        help="Path to the bootstrap registration token (preferred over env)",
    )
    parser.add_argument(
        "--exporter-allowed-host",
        action="append",
        dest="exporter_allowed_hosts",
        default=None,
        help="Exact hostname or CIDR allowed for exporter HTTP requests",
    )
    parser.add_argument(
        "--snmp-allowed-target",
        action="append",
        dest="snmp_allowed_targets",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed as an SNMP target",
    )
    parser.add_argument(
        "--windows-exporter-allowed-host",
        action="append",
        dest="windows_exporter_allowed_hosts",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed for windows_exporter",
    )
    parser.add_argument(
        "--windows-allowed-target",
        action="append",
        dest="windows_allowed_targets",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed for PSRP/CIM diagnostics",
    )
    parser.add_argument("--once", action="store_true")
    return parser.parse_args(argv)


def load_registration_token(token_file: str | None) -> str:
    if token_file:
        try:
            with open(token_file, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise SystemExit(
                f"Unable to read collector registration token file: {exc}"
            ) from exc
    else:
        token = os.getenv("ICHECK_COLLECTOR_REGISTRATION_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "Set ICHECK_COLLECTOR_REGISTRATION_TOKEN_FILE or "
            "ICHECK_COLLECTOR_REGISTRATION_TOKEN"
        )
    return token


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    capabilities = args.capabilities
    if capabilities is None:
        capabilities = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_CAPABILITIES",
                "http_json",
            ).split(",")
            if item.strip()
        ]
    if not capabilities:
        raise SystemExit("At least one collector capability is required")
    http_allowed_hosts = args.http_allowed_hosts
    if http_allowed_hosts is None:
        http_allowed_hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_HTTP_ALLOWED_HOSTS", ""
            ).split(",")
            if item.strip()
        ]
    exporter_allowed_hosts = args.exporter_allowed_hosts
    if exporter_allowed_hosts is None:
        exporter_allowed_hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_EXPORTER_ALLOWED_HOSTS",
                "127.0.0.1,localhost",
            ).split(",")
            if item.strip()
        ]
    snmp_allowed_targets = args.snmp_allowed_targets
    if snmp_allowed_targets is None:
        snmp_allowed_targets = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS",
                "",
            ).split(",")
            if item.strip()
        ]
    windows_exporter_allowed_hosts = args.windows_exporter_allowed_hosts
    if windows_exporter_allowed_hosts is None:
        windows_exporter_allowed_hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_WINDOWS_EXPORTER_ALLOWED_HOSTS",
                "",
            ).split(",")
            if item.strip()
        ]
    windows_allowed_targets = args.windows_allowed_targets
    if windows_allowed_targets is None:
        windows_allowed_targets = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS",
                "",
            ).split(",")
            if item.strip()
        ]
    if args.poll_seconds < 1 or args.poll_seconds > 300:
        raise SystemExit("--poll-seconds must be between 1 and 300")
    if args.lease_seconds < 15 or args.lease_seconds > 3600:
        raise SystemExit("--lease-seconds must be between 15 and 3600")
    if args.max_assignments < 1 or args.max_assignments > 20:
        raise SystemExit("--max-assignments must be between 1 and 20")

    client = ControlPlaneClient(args.control_plane)
    registration = client.request(
        "POST",
        "/api/v1/collector-workers/register",
        {
            "name": args.name,
            "site": args.site,
            "capabilities": capabilities,
            "labels": {"runtime": "python"},
        },
        extra_headers={
            "X-iCheck-Registration-Token": load_registration_token(
                args.registration_token_file
            )
        },
    )
    client.access_token = registration["access_token"]
    worker_id = registration["worker"]["id"]
    while True:
        run_once(
            client,
            worker_id,
            max_assignments=args.max_assignments,
            lease_seconds=args.lease_seconds,
            http_allowed_hosts=http_allowed_hosts,
            exporter_allowed_hosts=exporter_allowed_hosts,
            snmp_allowed_targets=snmp_allowed_targets,
            windows_exporter_allowed_hosts=windows_exporter_allowed_hosts,
            windows_allowed_targets=windows_allowed_targets,
        )
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
