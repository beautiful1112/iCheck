from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from prometheus_client.parser import text_string_to_metric_families
from pydantic import ConfigDict, Field, model_validator

from .schemas import APIModel
from .services.artifact_portability import trusted_digest_signature_message
from .services.mib_ingestion import extract_mib_collector_input
from .services.snmp_exporter_attestations import (
    attestation_statement_digest,
    canonical_hash,
)
from .snmp_attestation_schemas import (
    SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
    SNMPExporterAttestationStatement,
)


MAX_CONFIG_BYTES = 10_000_000
MAX_SCRAPE_BYTES = 10_000_000
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
VERSION_PATTERN = re.compile(
    r"(?i)\bversion(?:=|:|\s)+[\"']?v?([A-Za-z0-9][A-Za-z0-9_.+-]*)"
)


class AttestorProposal(APIModel):
    model_config = ConfigDict(extra="forbid")

    proposal_artifact_id: str = Field(min_length=1, max_length=36)
    proposal_version_id: str = Field(min_length=1, max_length=36)
    proposal_version: int = Field(ge=1)
    proposal_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mib_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generator_module_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exporter_module_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    generator_module: dict[str, Any]

    @model_validator(mode="after")
    def validate_generator_module(self) -> "AttestorProposal":
        module = self.generator_module
        if set(module) != {"walk", "max_repetitions", "retries", "timeout"}:
            raise ValueError("Attestor generator module has unsupported fields")
        walk = module.get("walk")
        if (
            not isinstance(walk, list)
            or not 1 <= len(walk) <= 500
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"(?:0|1|2)(?:\.(?:0|[1-9][0-9]{0,9})){1,127}", item)
                is None
                for item in walk
            )
            or len(set(walk)) != len(walk)
        ):
            raise ValueError("Attestor walk list is invalid")
        if not isinstance(module.get("max_repetitions"), int) or not (
            1 <= module["max_repetitions"] <= 50
        ):
            raise ValueError("Attestor max_repetitions is invalid")
        if not isinstance(module.get("retries"), int) or not (
            0 <= module["retries"] <= 5
        ):
            raise ValueError("Attestor retries is invalid")
        if (
            not isinstance(module.get("timeout"), str)
            or re.fullmatch(r"(?:[1-9]|[1-5][0-9]|60)s", module["timeout"])
            is None
        ):
            raise ValueError("Attestor timeout is invalid")
        if canonical_hash(module) != self.generator_module_sha256:
            raise ValueError("Attestor generator module hash does not match")
        return self


class CommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[..., CommandResult]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(newurl, code, "HTTP redirects are disabled", headers, fp)


def _sha256_file(path: Path, *, maximum: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            total += len(chunk)
            if maximum is not None and total > maximum:
                raise ValueError(f"{path.name} exceeds the permitted size")
            digest.update(chunk)
    return digest.hexdigest()


def _regular_absolute_path(
    value: str,
    label: str,
    *,
    executable: bool = False,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be an absolute regular file without symlinks")
    if executable and not os.access(path, os.X_OK):
        raise ValueError(f"{label} is not executable")
    return path


def _private_key(path_value: str) -> tuple[Ed25519PrivateKey, str]:
    path = _regular_absolute_path(path_value, "Attestor private key")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError("Attestor private key must not be group/world accessible")
    encoded = path.read_bytes()
    if len(encoded) > 4096:
        raise ValueError("Attestor private key file is oversized")
    try:
        key = serialization.load_pem_private_key(encoded, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Attestor private key must be an unencrypted PEM key"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Attestor private key must be Ed25519")
    raw_public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return key, hashlib.sha256(raw_public).hexdigest()


def _run(
    runner: CommandRunner,
    command: list[str],
    *,
    timeout_seconds: int,
    cwd: Path | None = None,
) -> CommandResult:
    try:
        result = runner(
            command,
            cwd=str(cwd) if cwd is not None else None,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("Attestor command exceeded its fixed timeout") from exc
    if result.returncode != 0:
        raise ValueError(
            f"Attestor command failed with exit code {result.returncode}"
        )
    return result


def _binary_version(path: Path, runner: CommandRunner) -> str:
    result = _run(runner, [str(path), "--version"], timeout_seconds=10)
    match = VERSION_PATTERN.search(f"{result.stdout}\n{result.stderr}")
    if match is None:
        raise ValueError(f"Could not parse version from {path.name}")
    return match.group(1)


def _bounded_yaml(path: Path) -> dict[str, Any]:
    encoded = path.read_bytes()
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ValueError("SNMP Exporter configuration exceeds the size limit")
    try:
        value = yaml.safe_load(encoded.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("SNMP Exporter configuration is not safe UTF-8 YAML") from exc
    if not isinstance(value, dict):
        raise ValueError("SNMP Exporter configuration root must be an object")
    return value


def compile_and_verify_module(
    proposal: AttestorProposal,
    *,
    mib_file: Path,
    shared_mib_dirs: list[Path],
    generator_binary: Path,
    installed_config: Path,
    generator_manifest: Path | None = None,
    runner: CommandRunner = subprocess.run,
) -> tuple[str, str, str]:
    mib_encoded = mib_file.read_bytes()
    if len(mib_encoded) > 1_000_000:
        raise ValueError("Staged MIB exceeds the permitted size")
    try:
        mib_text = mib_encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Staged MIB is not UTF-8") from exc
    mib = extract_mib_collector_input(mib_text)
    if mib.provenance["document_sha256"] != proposal.mib_document_sha256:
        raise ValueError("Staged MIB does not match the proposal hash")
    generator_hash = _sha256_file(generator_binary)
    if generator_manifest is not None:
        from .snmp_generator import GeneratorRuntime
        runtime = GeneratorRuntime.from_manifest(generator_manifest)
        runtime.validate()
        if runtime.generator != generator_binary or runtime.binary_sha256 != generator_hash:
            raise ValueError("Generator manifest does not bind the selected binary")
        generator_version = runtime.version
    else:
        try:
            generator_version = _binary_version(generator_binary, runner)
        except ValueError:
            raise ValueError("Generator does not expose a version; supply a protected generator manifest") from None
    for directory in shared_mib_dirs:
        if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
            raise ValueError("Shared MIB directories must be absolute real directories")
    with tempfile.TemporaryDirectory(prefix="icheck-snmp-attestor-") as raw:
        work = Path(raw)
        local_mibs = work / "mibs"
        local_mibs.mkdir(mode=0o700)
        staged_mib = local_mibs / "uploaded.mib"
        staged_mib.write_text(mib_text, encoding="utf-8")
        generator_config = work / "generator.yml"
        output_config = work / "snmp.yml"
        generator_config.write_text(
            yaml.safe_dump(
                {
                    "modules": {
                        proposal.exporter_module_name: proposal.generator_module
                    }
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        command = [str(generator_binary), "--fail-on-parse-errors", "generate"]
        for directory in [local_mibs, *shared_mib_dirs]:
            command.extend(["-m", str(directory)])
        command.extend(
            ["-g", str(generator_config), "-o", str(output_config)]
        )
        _run(runner, command, timeout_seconds=120, cwd=work)
        generated = _bounded_yaml(output_config)
        installed = _bounded_yaml(installed_config)
        generated_modules = generated.get("modules")
        installed_modules = installed.get("modules")
        if not isinstance(generated_modules, dict) or not isinstance(
            installed_modules, dict
        ):
            raise ValueError("SNMP Exporter configurations require a modules map")
        generated_module = generated_modules.get(proposal.exporter_module_name)
        installed_module = installed_modules.get(proposal.exporter_module_name)
        if not isinstance(generated_module, dict) or generated_module != installed_module:
            raise ValueError(
                "Installed SNMP Exporter module does not match generated output"
            )
        module_hash = canonical_hash(generated_module)
    return generator_version, generator_hash, module_hash


def _host_allowed(hostname: str, patterns: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for pattern in patterns:
        normalized = pattern.strip().rstrip(".").lower()
        if not normalized:
            continue
        if "/" in normalized and address is not None:
            try:
                if address in ipaddress.ip_network(normalized, strict=False):
                    return True
            except ValueError:
                continue
        elif normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


def _target_host(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"//{target}")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("SNMP target must be a host without credentials")
    if "://" in target and parsed.scheme not in {"udp", "udp6", "tcp", "tcp6"}:
        raise ValueError("SNMP target transport is unsupported")
    return parsed.hostname


def collect_live_evidence(
    *,
    exporter_url: str,
    target: str,
    auth_module: str,
    exporter_module_name: str,
    exporter_allowed_hosts: list[str],
    target_allowed_hosts: list[str],
    scrape_count: int = 3,
    timeout_seconds: int = 30,
    opener: Any | None = None,
) -> dict[str, Any]:
    parsed = urlsplit(exporter_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Exporter URL must be HTTP(S)")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Exporter URL must not contain credentials, query, or fragment")
    if not _host_allowed(parsed.hostname, exporter_allowed_hosts):
        raise ValueError("Exporter host is not allowlisted")
    if not _host_allowed(_target_host(target), target_allowed_hosts):
        raise ValueError("SNMP target is not allowlisted")
    if not NAME_PATTERN.fullmatch(auth_module) or not NAME_PATTERN.fullmatch(
        exporter_module_name
    ):
        raise ValueError("SNMP auth or module name is invalid")
    if not 3 <= scrape_count <= 10:
        raise ValueError("Attestor requires between three and ten scrapes")
    if not 1 <= timeout_seconds <= 60:
        raise ValueError("Attestor scrape timeout must be between 1 and 60 seconds")
    http = opener or build_opener(_NoRedirect())
    sample_count = 0
    series: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    label_names: set[str] = set()
    durations: list[int] = []
    bodies: list[dict[str, Any]] = []
    query = urlencode(
        {"target": target, "auth": auth_module, "module": exporter_module_name}
    )
    url = f"{exporter_url.rstrip('/')}/snmp?{query}"
    for index in range(scrape_count):
        request = Request(
            url,
            headers={
                "Accept": "text/plain; version=0.0.4",
                "User-Agent": "iCheck-snmp-attestor/0.1",
            },
            method="GET",
        )
        started = time.monotonic()
        with http.open(request, timeout=timeout_seconds) as response:
            body = response.read(MAX_SCRAPE_BYTES + 1)
        duration_ms = max(1, int((time.monotonic() - started) * 1000))
        if len(body) > MAX_SCRAPE_BYTES:
            raise ValueError("SNMP attestor scrape exceeded the response limit")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("SNMP attestor scrape is not UTF-8") from exc
        current_samples = 0
        for family in text_string_to_metric_families(text):
            for sample in family.samples:
                current_samples += 1
                labels = tuple(sorted((str(k), str(v)) for k, v in sample.labels.items()))
                series.add((sample.name, labels))
                label_names.update(str(key) for key in sample.labels)
        if current_samples < 1:
            raise ValueError("SNMP attestor scrape returned no samples")
        sample_count += current_samples
        durations.append(duration_ms)
        bodies.append(
            {
                "sequence": index + 1,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "sample_count": current_samples,
                "duration_ms": duration_ms,
            }
        )
    return {
        "successful_scrapes": scrape_count,
        "sample_count": sample_count,
        "series_count": len(series),
        "label_name_count": len(label_names),
        "maximum_scrape_duration_ms": max(durations),
        "timed_out_scrapes": 0,
        "evidence_sha256": canonical_hash(bodies),
    }


def build_signed_attestation(
    proposal: AttestorProposal,
    *,
    mib_file: Path,
    shared_mib_dirs: list[Path],
    generator_binary: Path,
    exporter_binary: Path,
    installed_config: Path,
    exporter_url: str,
    target: str,
    auth_module: str,
    exporter_allowed_hosts: list[str],
    target_allowed_hosts: list[str],
    installation_id: str,
    private_key_file: str,
    generator_manifest: Path | None = None,
    expires_hours: int = 24,
    scrape_count: int = 3,
    runner: CommandRunner = subprocess.run,
    opener: Any | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", installation_id):
        raise ValueError("Attestor installation ID is invalid")
    if not 1 <= expires_hours <= 168:
        raise ValueError("Attestor expiry must be between 1 and 168 hours")
    generator_version, generator_hash, module_hash = compile_and_verify_module(
        proposal,
        mib_file=mib_file,
        shared_mib_dirs=shared_mib_dirs,
        generator_binary=generator_binary,
        installed_config=installed_config,
        generator_manifest=generator_manifest,
        runner=runner,
    )
    exporter_version = _binary_version(exporter_binary, runner)
    if generator_manifest is not None and exporter_version != generator_version:
        raise ValueError("SNMP generator and exporter versions do not match")
    exporter_hash = _sha256_file(exporter_binary)
    tested_at = datetime.now(UTC)
    evidence = collect_live_evidence(
        exporter_url=exporter_url,
        target=target,
        auth_module=auth_module,
        exporter_module_name=proposal.exporter_module_name,
        exporter_allowed_hosts=exporter_allowed_hosts,
        target_allowed_hosts=target_allowed_hosts,
        scrape_count=scrape_count,
        opener=opener,
    )
    issued_at = datetime.now(UTC)
    key, fingerprint = _private_key(private_key_file)
    statement = SNMPExporterAttestationStatement(
        proposal_artifact_id=proposal.proposal_artifact_id,
        proposal_version_id=proposal.proposal_version_id,
        proposal_version=proposal.proposal_version,
        proposal_content_hash=proposal.proposal_content_hash,
        mib_document_sha256=proposal.mib_document_sha256,
        generator_module_sha256=proposal.generator_module_sha256,
        exporter_module_name=proposal.exporter_module_name,
        generator_name="prometheus/snmp_exporter/generator",
        generator_version=generator_version,
        generator_binary_sha256=generator_hash,
        generated_config_sha256=module_hash,
        installed_config_sha256=module_hash,
        exporter_version=exporter_version,
        exporter_binary_sha256=exporter_hash,
        installation_id=installation_id,
        target_sha256=hashlib.sha256(target.encode("utf-8")).hexdigest(),
        auth_module_sha256=hashlib.sha256(auth_module.encode("utf-8")).hexdigest(),
        tested_at=tested_at,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=expires_hours),
        nonce=secrets.token_hex(24),
        **evidence,
    )
    digest = attestation_statement_digest(statement)
    signature = key.sign(
        trusted_digest_signature_message(
            SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
            digest,
        )
    )
    return {
        "format_version": SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
        "statement": statement.model_dump(mode="json"),
        "digest_sha256": digest,
        "signature": {
            "algorithm": "ed25519",
            "key_fingerprint_sha256": fingerprint,
            "signed_digest_sha256": digest,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile, verify, live-test, and sign an SNMP Exporter proposal"
    )
    parser.add_argument("--proposal-file", required=True)
    parser.add_argument("--mib-file", required=True)
    parser.add_argument("--shared-mib-dir", action="append", default=[])
    parser.add_argument("--generator-binary", required=True)
    parser.add_argument("--generator-manifest", help="Protected version/digest manifest for generators without --version")
    parser.add_argument("--exporter-binary", required=True)
    parser.add_argument("--installed-config", required=True)
    parser.add_argument("--exporter-url", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--auth-module", required=True)
    parser.add_argument("--exporter-allowed-hosts", required=True)
    parser.add_argument("--target-allowed-hosts", required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--private-key-file", required=True)
    parser.add_argument("--expires-hours", type=int, default=24)
    parser.add_argument("--scrape-count", type=int, default=3)
    parser.add_argument(
        "--output-file",
        help="Absolute path for an atomically replaced mode-0600 signed envelope",
    )
    return parser


def _write_document(document: dict[str, Any], output_file: str | None) -> None:
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if output_file is None:
        sys.stdout.buffer.write(encoded)
        return
    destination = Path(output_file)
    parent = destination.parent
    if (
        not destination.is_absolute()
        or destination.is_symlink()
        or parent.is_symlink()
        or not parent.is_dir()
    ):
        raise ValueError(
            "Attestation output must be an absolute non-symlink path in a real directory"
        )
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=parent,
        )
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    try:
        proposal_path = _regular_absolute_path(args.proposal_file, "Proposal file")
        proposal_encoded = proposal_path.read_bytes()
        if len(proposal_encoded) > 262_144:
            raise ValueError("Proposal file exceeds 262144 bytes")
        proposal = AttestorProposal.model_validate_json(proposal_encoded)
        document = build_signed_attestation(
            proposal,
            mib_file=_regular_absolute_path(args.mib_file, "MIB file"),
            shared_mib_dirs=[Path(item) for item in args.shared_mib_dir],
            generator_binary=_regular_absolute_path(
                args.generator_binary,
                "Generator binary",
                executable=True,
            ),
            generator_manifest=Path(args.generator_manifest) if args.generator_manifest else None,
            exporter_binary=_regular_absolute_path(
                args.exporter_binary,
                "SNMP Exporter binary",
                executable=True,
            ),
            installed_config=_regular_absolute_path(
                args.installed_config,
                "Installed SNMP Exporter configuration",
            ),
            exporter_url=args.exporter_url,
            target=args.target,
            auth_module=args.auth_module,
            exporter_allowed_hosts=_csv(args.exporter_allowed_hosts),
            target_allowed_hosts=_csv(args.target_allowed_hosts),
            installation_id=args.installation_id,
            private_key_file=args.private_key_file,
            expires_hours=args.expires_hours,
            scrape_count=args.scrape_count,
        )
        _write_document(document, args.output_file)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"icheck-snmp-attestor: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
