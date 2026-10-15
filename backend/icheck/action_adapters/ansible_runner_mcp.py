from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Protocol
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from ..mcp_schemas import MCP_PROTOCOL_VERSION


CATALOG_CONTRACT = "icheck.ansible-catalog/v1"
MAX_MANIFEST_BYTES = 1_000_000
MAX_RPC_BYTES = 128_000
MAX_PROJECT_FILES = 5_000
MAX_PROJECT_BYTES = 100_000_000
MAX_EVENT_BYTES = 256_000
MAX_OPERATIONS = 20
MAX_TOTAL_TARGETS = 2_000
STAGES = ("precheck", "dry_run", "apply", "postcheck", "rollback")
OUTCOME_LOOKUP_TOOL = "ansible.action_outcome.lookup"
READ_ONLY_STAGES = frozenset({"precheck", "dry_run", "postcheck"})
TARGET_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$"
SAFE_PARAMETER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SENSITIVE_PARAMETER_PARTS = frozenset(
    {
        "authorization",
        "community",
        "credential",
        "key",
        "passphrase",
        "password",
        "private",
        "secret",
        "token",
    }
)
CREDENTIAL_HEADERS = {
    "x-icheck-ansible-user": "ansible_user",
    "x-icheck-ansible-password": "ansible_password",
    "x-icheck-ansible-become-password": "ansible_become_password",
    "x-icheck-ansible-network-os": "ansible_network_os",
}


class AdapterError(RuntimeError):
    pass


class ActionExecutionFailed(AdapterError):
    pass


class ActionOutcomeUnknown(AdapterError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _safe_relative_path(value: str) -> str:
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError("paths must be non-empty relative paths without traversal")
    return candidate.as_posix()


class CatalogInventory(_StrictModel):
    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_relative_path(value)


class OperationPlaybooks(_StrictModel):
    precheck: str = Field(min_length=1, max_length=512)
    apply: str = Field(min_length=1, max_length=512)
    postcheck: str = Field(min_length=1, max_length=512)
    rollback: str = Field(min_length=1, max_length=512)

    @field_validator("precheck", "apply", "postcheck", "rollback")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_relative_path(value)


def _validate_parameter_schema(schema: dict[str, Any]) -> dict[str, Any]:
    Draft202012Validator.check_schema(schema)
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        raise ValueError("parameters_schema must be a closed object schema")
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise ValueError("parameters_schema requires properties and required")
    if len(properties) > 30 or set(required) != set(properties):
        raise ValueError("every bounded operation parameter must be required")
    for name, definition in properties.items():
        if not SAFE_PARAMETER_NAME.fullmatch(name):
            raise ValueError(f"unsafe operation parameter name {name!r}")
        name_parts = frozenset(name.split("_"))
        if (
            name.startswith(("ansible_", "icheck_"))
            or name_parts & SENSITIVE_PARAMETER_PARTS
        ):
            raise ValueError(f"secret or reserved operation parameter {name!r} is forbidden")
        if not isinstance(definition, dict):
            raise ValueError(f"operation parameter {name!r} has an invalid schema")
        parameter_type = definition.get("type")
        if parameter_type not in {"string", "integer", "number", "boolean"}:
            raise ValueError("operation parameters must be scalar")
        if (
            parameter_type == "string"
            and not 1 <= definition.get("maxLength", 0) <= 4096
        ):
            raise ValueError("string operation parameters require maxLength <= 4096")
        if parameter_type in {"integer", "number"} and not (
            isinstance(definition.get("minimum"), (int, float))
            and isinstance(definition.get("maximum"), (int, float))
        ):
            raise ValueError("numeric operation parameters require minimum and maximum")
    return schema


class AnsibleOperation(_StrictModel):
    operation_id: str = Field(
        min_length=1,
        max_length=180,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    description: str = Field(min_length=1, max_length=1000)
    allowed_targets: list[str] = Field(min_length=1, max_length=1000)
    parameters_schema: dict[str, Any]
    playbooks: OperationPlaybooks
    timeout_seconds: int = Field(default=300, ge=1, le=1800)

    @field_validator("parameters_schema")
    @classmethod
    def validate_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_parameter_schema(value)

    @field_validator("allowed_targets")
    @classmethod
    def validate_targets(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(
            re.fullmatch(TARGET_PATTERN, item) is None for item in value
        ):
            raise ValueError("allowed_targets must contain unique inventory host aliases")
        return value


class AnsibleCatalog(_StrictModel):
    contract: Literal["icheck.ansible-catalog/v1"] = CATALOG_CONTRACT
    project_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory: CatalogInventory
    operations: list[AnsibleOperation] = Field(min_length=1, max_length=MAX_OPERATIONS)

    @model_validator(mode="after")
    def unique_operations(self) -> "AnsibleCatalog":
        names = [item.operation_id for item in self.operations]
        if len(set(names)) != len(names):
            raise ValueError("operation_id values must be unique")
        if sum(len(item.allowed_targets) for item in self.operations) > MAX_TOTAL_TARGETS:
            raise ValueError("catalog contains too many operation target bindings")
        return self


class AnsibleAdapterSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ICHECK_ANSIBLE_ADAPTER_",
        extra="ignore",
    )

    environment: str = "development"
    manifest_path: str = "/etc/icheck/ansible/catalog.json"
    project_root: str = "/etc/icheck/ansible/project"
    inventory_root: str = "/etc/icheck/ansible/inventory"
    private_data_root: str = "/var/lib/icheck/ansible-adapter"
    runner_path: str = "/opt/icheck/.venv/bin/ansible-runner"
    runner_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    auth_token_file: str | None = None
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8766, ge=1, le=65535)
    max_output_bytes: int = Field(default=1_000_000, ge=10_000, le=10_000_000)
    max_events: int = Field(default=5_000, ge=1, le=50_000)

    @field_validator(
        "manifest_path",
        "project_root",
        "inventory_root",
        "private_data_root",
        "runner_path",
    )
    @classmethod
    def absolute_paths(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("Ansible adapter filesystem paths must be absolute")
        return value

    @field_validator("auth_token_file")
    @classmethod
    def absolute_token_path(cls, value: str | None) -> str | None:
        if value is not None and not Path(value).is_absolute():
            raise ValueError("auth_token_file must be absolute")
        return value

    @model_validator(mode="after")
    def production_guards(self) -> "AnsibleAdapterSettings":
        if self.environment.strip().lower() == "production":
            if not self.auth_token_file:
                raise ValueError("production Ansible adapter requires auth_token_file")
            if not self.runner_sha256:
                raise ValueError("production Ansible adapter requires runner_sha256")
            if self.bind_host not in {"127.0.0.1", "::1"}:
                raise ValueError("production Ansible adapter must bind to loopback")
        return self


@dataclass(frozen=True)
class RunnerRequest:
    operation_id: str
    stage: str
    target: str
    variables: dict[str, Any]
    credentials: dict[str, str]
    playbook: str
    timeout_seconds: int
    check_mode: bool


@dataclass(frozen=True)
class RunnerOutcome:
    status: Literal["successful", "failed", "timed_out"]
    changed: bool
    changed_tasks: int
    failed_tasks: int
    event_count: int
    duration_ms: int
    run_id: str
    replayed: bool = False


class RunnerBackend(Protocol):
    def run(self, request: RunnerRequest) -> RunnerOutcome: ...


def _regular_file_bytes(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > maximum:
            raise AdapterError(f"unsafe or oversized file: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise AdapterError(f"oversized file: {path}")
        return data
    finally:
        os.close(descriptor)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(
        _regular_file_bytes(path, maximum=MAX_PROJECT_BYTES)
    ).hexdigest()


def project_tree_sha256(root: Path) -> str:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise AdapterError("Ansible project root is not a directory")
    entries: list[tuple[str, bytes]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise AdapterError("Ansible project cannot contain symbolic links")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        data = _regular_file_bytes(path, maximum=MAX_PROJECT_BYTES)
        total_bytes += len(data)
        entries.append((relative, hashlib.sha256(data).digest()))
        if len(entries) > MAX_PROJECT_FILES or total_bytes > MAX_PROJECT_BYTES:
            raise AdapterError("Ansible project exceeds bounded catalog limits")
    digest = hashlib.sha256()
    for relative, content_hash in entries:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content_hash)
        digest.update(b"\n")
    return digest.hexdigest()


def load_catalog(settings: AnsibleAdapterSettings) -> AnsibleCatalog:
    manifest_path = Path(settings.manifest_path)
    document = json.loads(
        _regular_file_bytes(manifest_path, maximum=MAX_MANIFEST_BYTES).decode("utf-8")
    )
    catalog = AnsibleCatalog.model_validate(document)
    validate_catalog_files(settings, catalog)
    return catalog


def _resolved_under(root: Path, relative: str) -> Path:
    resolved_root = root.resolve(strict=True)
    candidate = (resolved_root / relative).resolve(strict=True)
    if not candidate.is_relative_to(resolved_root):
        raise AdapterError("catalog path escaped its configured root")
    return candidate


def validate_catalog_files(
    settings: AnsibleAdapterSettings,
    catalog: AnsibleCatalog,
) -> None:
    project_root = Path(settings.project_root)
    if not secrets.compare_digest(
        project_tree_sha256(project_root),
        catalog.project_sha256,
    ):
        raise AdapterError("Ansible project hash does not match the catalog")
    inventory = _resolved_under(Path(settings.inventory_root), catalog.inventory.path)
    if not secrets.compare_digest(file_sha256(inventory), catalog.inventory.sha256):
        raise AdapterError("Ansible inventory hash does not match the catalog")
    for operation in catalog.operations:
        for relative in {
            operation.playbooks.precheck,
            operation.playbooks.apply,
            operation.playbooks.postcheck,
            operation.playbooks.rollback,
        }:
            playbook = _resolved_under(project_root, relative)
            if not playbook.is_file():
                raise AdapterError(f"catalog playbook is not a file: {relative}")


def _secure_json(path: Path, value: Any) -> None:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise AdapterError("Ansible private-data directory must be mode 0700")


def validate_runner(settings: AnsibleAdapterSettings) -> Path:
    runner = Path(settings.runner_path)
    if (
        not runner.is_absolute()
        or not runner.is_file()
        or not os.access(runner, os.X_OK)
    ):
        raise AdapterError("ansible-runner executable is unavailable")
    if settings.runner_sha256 and not secrets.compare_digest(
        file_sha256(runner),
        settings.runner_sha256,
    ):
        raise AdapterError("ansible-runner executable hash has drifted")
    return runner


class SubprocessAnsibleRunnerBackend:
    """Runs pinned playbooks through ansible-runner without a shell."""

    def __init__(self, settings: AnsibleAdapterSettings, catalog: AnsibleCatalog):
        self.settings = settings
        self.catalog = catalog

    def _event_summary(self, artifact_root: Path) -> tuple[bool, int, int, int]:
        changed = False
        changed_tasks = 0
        failed_tasks = 0
        event_count = 0
        event_root = artifact_root / "job_events"
        if not event_root.exists():
            return changed, changed_tasks, failed_tasks, event_count
        if event_root.is_symlink() or not event_root.is_dir():
            raise AdapterError("ansible-runner emitted an unsafe event directory")
        for path in sorted(event_root.iterdir(), key=lambda item: item.name):
            if event_count >= self.settings.max_events:
                raise AdapterError("ansible-runner emitted too many events")
            if path.is_symlink() or not path.is_file():
                raise AdapterError("ansible-runner emitted an unsafe event artifact")
            document = json.loads(
                _regular_file_bytes(path, maximum=MAX_EVENT_BYTES).decode("utf-8")
            )
            if not isinstance(document, dict):
                raise AdapterError("ansible-runner emitted an invalid event artifact")
            event_count += 1
            event = document.get("event")
            event_data = document.get("event_data", {})
            result = event_data.get("res", {}) if isinstance(event_data, dict) else {}
            if isinstance(result, dict) and result.get("changed") is True:
                changed = True
                changed_tasks += 1
            if event in {"runner_on_failed", "runner_on_unreachable"}:
                failed_tasks += 1
        return changed, changed_tasks, failed_tasks, event_count

    def run(self, request: RunnerRequest) -> RunnerOutcome:
        runner = validate_runner(self.settings)
        private_root = Path(self.settings.private_data_root)
        _secure_private_directory(private_root)
        run_id = uuid4().hex
        job_path = Path(tempfile.mkdtemp(prefix="job-", dir=private_root))
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        try:
            (job_path / "env").mkdir(mode=0o700)
            (job_path / "artifacts").mkdir(mode=0o700)
            os.symlink(
                Path(self.settings.project_root).resolve(strict=True),
                job_path / "project",
            )
            inventory = _resolved_under(
                Path(self.settings.inventory_root),
                self.catalog.inventory.path,
            )
            os.symlink(inventory, job_path / "inventory")
            extravars = {"icheck_target": request.target, **request.variables}
            extravars.update(request.credentials)
            _secure_json(job_path / "env" / "extravars", extravars)
            _secure_json(
                job_path / "env" / "settings",
                {
                    "job_timeout": request.timeout_seconds,
                    "pexpect_timeout": min(request.timeout_seconds, 60),
                    "suppress_ansible_output": True,
                },
            )
            if request.check_mode:
                descriptor = os.open(
                    job_path / "env" / "cmdline",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    os.write(descriptor, b"--check --diff")
                finally:
                    os.close(descriptor)
            command = [
                str(runner),
                "run",
                str(job_path),
                "-p",
                request.playbook,
                "--limit",
                request.target,
                "--artifact-dir",
                str(job_path / "artifacts"),
                "--ident",
                run_id,
                "--rotate-artifacts",
                "1",
            ]
            clean_environment = {
                "HOME": str(job_path),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PATH": (
                    f"{runner.parent}:"
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ),
            }
            process = subprocess.Popen(
                command,
                cwd=job_path,
                env=clean_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=request.timeout_seconds + 5)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                return_code = -signal.SIGKILL
            artifact_root = job_path / "artifacts" / run_id
            changed, changed_tasks, failed_tasks, event_count = self._event_summary(
                artifact_root
            )
            status: Literal["successful", "failed", "timed_out"]
            if timed_out:
                status = "timed_out"
            elif return_code == 0 and failed_tasks == 0:
                status = "successful"
            else:
                status = "failed"
            return RunnerOutcome(
                status=status,
                changed=changed,
                changed_tasks=changed_tasks,
                failed_tasks=failed_tasks,
                event_count=event_count,
                duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                run_id=run_id,
            )
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            shutil.rmtree(job_path, ignore_errors=True)


class IdempotencyLedger:
    def __init__(self, root: Path):
        self.root = root

    def _write(self, path: Path, document: dict[str, Any]) -> None:
        temporary = path.with_suffix(f".{uuid4().hex}.tmp")
        try:
            _secure_json(temporary, document)
            os.replace(temporary, path)
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        value = json.loads(_regular_file_bytes(path, maximum=MAX_EVENT_BYTES).decode("utf-8"))
        if not isinstance(value, dict):
            raise AdapterError("Ansible action ledger record is invalid")
        return value

    def lookup(self, source_tool_call_id: str) -> dict[str, Any]:
        """Report only a durably recorded successful write; never infer absence."""
        _secure_private_directory(self.root)
        source_identity = hashlib.sha256(source_tool_call_id.encode("utf-8")).hexdigest()
        source_path = self.root / f"source-{source_identity}.json"
        observed_at = datetime.now(UTC).isoformat()
        result = {
            "source_tool_call_id": source_tool_call_id,
            "provider_outcome": "unknown",
            "provider_reference": None,
            "observed_at": observed_at,
        }
        if not source_path.exists():
            return result
        source = self._read(source_path)
        primary_identity = source.get("primary_identity")
        if (
            source.get("source_tool_call_id") != source_tool_call_id
            or not isinstance(primary_identity, str)
            or re.fullmatch(r"[0-9a-f]{64}", primary_identity) is None
        ):
            raise AdapterError("Ansible action correlation record is invalid")
        primary_path = self.root / f"{primary_identity}.json"
        if not primary_path.exists():
            return result
        primary = self._read(primary_path)
        if primary.get("source_tool_call_id") != source_tool_call_id:
            raise AdapterError("Ansible action correlation record does not match")
        outcome = primary.get("outcome")
        if (
            primary.get("status") == "terminal"
            and isinstance(outcome, dict)
            and outcome.get("status") == "successful"
            and outcome.get("failed_tasks") == 0
            and isinstance(outcome.get("run_id"), str)
            and isinstance(primary.get("completed_at"), str)
        ):
            return {
                **result,
                "provider_outcome": "applied",
                "provider_reference": outcome["run_id"],
                "observed_at": datetime.now(UTC).isoformat(),
            }
        return result

    def execute(
        self,
        *,
        operation_id: str,
        idempotency_key: str,
        source_tool_call_id: str,
        fingerprint: str,
        callback: Callable[[], RunnerOutcome],
    ) -> RunnerOutcome:
        _secure_private_directory(self.root)
        identity = hashlib.sha256(
            f"{operation_id}\0{idempotency_key}".encode("utf-8")
        ).hexdigest()
        lock_path = self.root / f"{identity}.lock"
        record_path = self.root / f"{identity}.json"
        source_identity = hashlib.sha256(source_tool_call_id.encode("utf-8")).hexdigest()
        source_path = self.root / f"source-{source_identity}.json"
        source_lock_path = self.root / f"source-{source_identity}.lock"
        descriptors: list[int] = []
        try:
            for path in sorted((lock_path, source_lock_path)):
                descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
                descriptors.append(descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            source = self._read(source_path) if source_path.exists() else None
            if source is not None and (
                source.get("source_tool_call_id") != source_tool_call_id
                or source.get("primary_identity") != identity
            ):
                raise AdapterError("Tool-call correlation key was already used for another action")
            if record_path.exists():
                record = self._read(record_path)
                if not secrets.compare_digest(record.get("fingerprint", ""), fingerprint):
                    raise AdapterError("idempotency key was already used for another action")
                if (
                    source is None
                    or record.get("source_tool_call_id") != source_tool_call_id
                ):
                    raise ActionOutcomeUnknown("a previous action cannot be correlated to this Tool call")
                if record.get("status") == "terminal":
                    return replace(
                        RunnerOutcome(**record["outcome"]),
                        replayed=True,
                    )
                raise ActionOutcomeUnknown(
                    "a previous action with this idempotency key has unknown outcome"
                )
            if source is not None:
                raise ActionOutcomeUnknown("a correlated action has unknown outcome")
            self._write(source_path, {
                "source_tool_call_id": source_tool_call_id,
                "primary_identity": identity,
            })
            self._write(
                record_path,
                {
                    "fingerprint": fingerprint,
                    "source_tool_call_id": source_tool_call_id,
                    "status": "running",
                },
            )
            try:
                outcome = callback()
            except Exception:
                self._write(
                    record_path,
                    {
                        "fingerprint": fingerprint,
                        "source_tool_call_id": source_tool_call_id,
                        "status": "outcome_unknown",
                    },
                )
                raise
            self._write(
                record_path,
                {
                    "fingerprint": fingerprint,
                    "source_tool_call_id": source_tool_call_id,
                    "status": "terminal",
                    "outcome": asdict(outcome),
                    "completed_at": datetime.now(UTC).isoformat(),
                },
            )
            return outcome
        finally:
            for descriptor in reversed(descriptors):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "success",
            "status",
            "changed",
            "changed_tasks",
            "failed_tasks",
            "event_count",
            "duration_ms",
            "run_id",
            "operation",
            "stage",
            "catalog_sha256",
            "replayed",
        ],
        "properties": {
            "success": {"type": "boolean"},
            "status": {"type": "string", "enum": ["successful", "failed", "timed_out"]},
            "changed": {"type": "boolean"},
            "changed_tasks": {"type": "integer", "minimum": 0},
            "failed_tasks": {"type": "integer", "minimum": 0},
            "event_count": {"type": "integer", "minimum": 0},
            "duration_ms": {"type": "integer", "minimum": 0},
            "run_id": {"type": "string", "minLength": 1, "maxLength": 64},
            "operation": {"type": "string", "minLength": 1, "maxLength": 180},
            "stage": {"type": "string", "enum": list(STAGES)},
            "catalog_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "replayed": {"type": "boolean"},
        },
    }


def _lookup_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["source_tool_call_id"],
        "properties": {
            "source_tool_call_id": {"type": "string", "minLength": 1, "maxLength": 36},
        },
    }


def _lookup_output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "source_tool_call_id", "provider_outcome", "provider_reference", "observed_at",
        ],
        "properties": {
            "source_tool_call_id": {"type": "string", "minLength": 1, "maxLength": 36},
            "provider_outcome": {"type": "string", "enum": ["applied", "unknown"]},
            "provider_reference": {"type": ["string", "null"], "maxLength": 255},
            "observed_at": {"type": "string", "format": "date-time"},
        },
    }


def _input_schema(operation: AnsibleOperation, stage: str) -> dict[str, Any]:
    properties = {
        "target": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "enum": operation.allowed_targets,
        },
        **operation.parameters_schema["properties"],
    }
    required = ["target", *operation.parameters_schema["required"]]
    if stage == "apply":
        properties["idempotency_key"] = {
            "type": "string",
            "minLength": 8,
            "maxLength": 512,
        }
        required.append("idempotency_key")
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


class AnsibleMCPRuntime:
    def __init__(
        self,
        settings: AnsibleAdapterSettings,
        catalog: AnsibleCatalog,
        backend: RunnerBackend,
    ):
        self.settings = settings
        self.catalog = catalog
        self.backend = backend
        self.catalog_sha256 = _canonical_hash(catalog.model_dump(mode="json"))
        self.ledger = IdempotencyLedger(
            Path(settings.private_data_root) / "idempotency"
        )
        self.tools: dict[str, tuple[AnsibleOperation, str]] = {}
        for operation in catalog.operations:
            for stage in STAGES:
                name = f"ansible.{operation.operation_id}.{stage}"
                if len(name) > 255:
                    raise AdapterError("derived MCP tool name exceeds 255 characters")
                self.tools[name] = (operation, stage)

    def advertisements(self) -> list[dict[str, Any]]:
        descriptions = {
            "precheck": "Read-only pre-change validation",
            "dry_run": "Ansible check-mode simulation",
            "apply": "Idempotent approved change execution",
            "postcheck": "Read-only post-change verification",
            "rollback": "Separately approved idempotent rollback",
        }
        tools = [
            {
                "name": name,
                "description": f"{descriptions[stage]}: {operation.description}",
                "inputSchema": _input_schema(operation, stage),
                "outputSchema": _output_schema(),
            }
            for name, (operation, stage) in sorted(self.tools.items())
        ]
        tools.append({
            "name": OUTCOME_LOOKUP_TOOL,
            "description": "Read-only lookup of the adapter's durable write ledger by iCheck Tool-call ID",
            "inputSchema": _lookup_input_schema(),
            "outputSchema": _lookup_output_schema(),
        })
        return sorted(tools, key=lambda item: item["name"])

    def _credentials(self, headers: Mapping[str, str]) -> dict[str, str]:
        credentials: dict[str, str] = {}
        for header, variable in CREDENTIAL_HEADERS.items():
            value = headers.get(header)
            if value:
                if "\r" in value or "\n" in value or len(value) > 4096:
                    raise AdapterError("unsafe Ansible credential header")
                credentials[variable] = value
        return credentials

    def call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        headers: Mapping[str, str],
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if tool_name == OUTCOME_LOOKUP_TOOL:
            errors = list(Draft202012Validator(_lookup_input_schema()).iter_errors(arguments))
            if errors:
                raise AdapterError(f"invalid outcome lookup arguments: {errors[0].message}")
            return self.ledger.lookup(arguments["source_tool_call_id"])
        selected = self.tools.get(tool_name)
        if selected is None:
            raise AdapterError("unknown Ansible catalog tool")
        operation, stage = selected
        errors = sorted(
            Draft202012Validator(_input_schema(operation, stage)).iter_errors(arguments),
            key=lambda item: list(item.path),
        )
        if errors:
            raise AdapterError(f"invalid Ansible tool arguments: {errors[0].message}")
        source_tool_call_id: str | None = None
        if stage in {"apply", "rollback"}:
            candidate = (metadata or {}).get("icheck/toolCallId")
            if not isinstance(candidate, str) or not 1 <= len(candidate) <= 36:
                raise AdapterError("state-changing action requires icheck/toolCallId MCP metadata")
            source_tool_call_id = candidate
        validate_catalog_files(self.settings, self.catalog)
        target = arguments["target"]
        variables = {
            key: value
            for key, value in arguments.items()
            if key not in {"target", "idempotency_key"}
        }
        playbook_stage = "apply" if stage == "dry_run" else stage
        request = RunnerRequest(
            operation_id=operation.operation_id,
            stage=stage,
            target=target,
            variables=variables,
            credentials=self._credentials(headers),
            playbook=getattr(operation.playbooks, playbook_stage),
            timeout_seconds=operation.timeout_seconds,
            check_mode=stage in READ_ONLY_STAGES,
        )

        def execute() -> RunnerOutcome:
            return self.backend.run(request)

        if stage in {"apply", "rollback"}:
            idempotency_key = (
                arguments["idempotency_key"] if stage == "apply"
                else source_tool_call_id
            )
            fingerprint = _canonical_hash(
                {
                    "operation": operation.operation_id,
                    **({"stage": "rollback"} if stage == "rollback" else {}),
                    "target": target,
                    "variables": variables,
                    "catalog_sha256": self.catalog_sha256,
                }
            )
            outcome = self.ledger.execute(
                operation_id=(
                    operation.operation_id if stage == "apply"
                    else f"{operation.operation_id}.rollback"
                ),
                idempotency_key=idempotency_key,
                source_tool_call_id=source_tool_call_id,
                fingerprint=fingerprint,
                callback=execute,
            )
        else:
            outcome = execute()
        success = outcome.status == "successful" and outcome.failed_tasks == 0
        if stage == "apply" and not success:
            raise ActionExecutionFailed("approved Ansible action did not complete")
        result = {
            "success": success,
            "status": outcome.status,
            "changed": outcome.changed,
            "changed_tasks": outcome.changed_tasks,
            "failed_tasks": outcome.failed_tasks,
            "event_count": outcome.event_count,
            "duration_ms": outcome.duration_ms,
            "run_id": outcome.run_id,
            "operation": operation.operation_id,
            "stage": stage,
            "catalog_sha256": self.catalog_sha256,
            "replayed": outcome.replayed,
        }
        if (
            len(json.dumps(result, separators=(",", ":")).encode("utf-8"))
            > self.settings.max_output_bytes
        ):
            raise AdapterError("Ansible structured result exceeds the configured limit")
        return result


def _load_auth_token(settings: AnsibleAdapterSettings) -> str | None:
    if not settings.auth_token_file:
        return None
    path = Path(settings.auth_token_file)
    details = path.stat()
    if settings.environment.strip().lower() == "production" and details.st_mode & 0o077:
        raise AdapterError("Ansible adapter token file must not be group/world accessible")
    token = _regular_file_bytes(path, maximum=8192).decode("utf-8").strip()
    if len(token) < 16:
        raise AdapterError("Ansible adapter token is missing or too short")
    return token


def _authorize(settings: AnsibleAdapterSettings, headers: Mapping[str, str]) -> None:
    expected = _load_auth_token(settings)
    if expected is None:
        return
    supplied = headers.get("authorization", "")
    if not supplied.startswith("Bearer ") or not secrets.compare_digest(
        supplied.removeprefix("Bearer "), expected
    ):
        raise AdapterError("Ansible adapter authentication failed")


def create_app(
    settings: AnsibleAdapterSettings,
    catalog: AnsibleCatalog,
    backend: RunnerBackend | None = None,
) -> FastAPI:
    runtime = AnsibleMCPRuntime(
        settings,
        catalog,
        backend or SubprocessAnsibleRunnerBackend(settings, catalog),
    )
    app = FastAPI(
        title="iCheck Ansible Runner MCP Adapter",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        validate_catalog_files(settings, catalog)
        validate_runner(settings)
        return {
            "status": "healthy",
            "contract": CATALOG_CONTRACT,
            "catalog_sha256": runtime.catalog_sha256,
            "tool_count": len(runtime.advertisements()),
            "runner_available": True,
        }

    @app.post("/rpc")
    async def rpc(request: Request) -> JSONResponse:
        request_id: Any = None
        try:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_RPC_BYTES:
                raise AdapterError("MCP request is too large")
            body = await request.body()
            if len(body) > MAX_RPC_BYTES:
                raise AdapterError("MCP request is too large")
            document = json.loads(body.decode("utf-8"))
            if not isinstance(document, dict):
                raise AdapterError("MCP request must be a JSON object")
            request_id = document.get("id")
            if (
                document.get("jsonrpc") != "2.0"
                or not isinstance(request_id, (str, int))
                or isinstance(request_id, str)
                and len(request_id) > 128
            ):
                raise AdapterError("invalid JSON-RPC envelope")
            if request.headers.get("mcp-protocol-version") != MCP_PROTOCOL_VERSION:
                raise AdapterError("unsupported MCP protocol version")
            _authorize(settings, request.headers)
            method = document.get("method")
            if request.headers.get("mcp-method") != method:
                raise AdapterError("MCP method header does not match request")
            params = document.get("params", {})
            if not isinstance(params, dict):
                raise AdapterError("MCP params must be an object")
            if method == "tools/list":
                result: dict[str, Any] = {"tools": runtime.advertisements()}
            elif method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments")
                metadata = params.get("_meta", {})
                if (
                    not isinstance(name, str)
                    or not isinstance(arguments, dict)
                    or not isinstance(metadata, dict)
                    or request.headers.get("mcp-name") != name
                ):
                    raise AdapterError("invalid MCP tool call")
                try:
                    structured = await run_in_threadpool(
                        runtime.call,
                        name,
                        arguments,
                        request.headers,
                        metadata,
                    )
                except ActionExecutionFailed:
                    result = {
                        "content": [{"type": "text", "text": "Approved action failed."}],
                        "isError": True,
                    }
                else:
                    result = {
                        "content": [{"type": "text", "text": "Bounded Ansible result."}],
                        "structuredContent": structured,
                        "isError": False,
                    }
            else:
                raise AdapterError("unsupported MCP method")
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
            return JSONResponse(
                response,
                headers={"MCP-Protocol-Version": MCP_PROTOCOL_VERSION},
            )
        except (
            AdapterError,
            ActionOutcomeUnknown,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(exc)},
            }
            return JSONResponse(
                response,
                status_code=400,
                headers={"MCP-Protocol-Version": MCP_PROTOCOL_VERSION},
            )

    return app


def main() -> None:
    settings = AnsibleAdapterSettings()
    catalog = load_catalog(settings)
    validate_runner(settings)
    _secure_private_directory(Path(settings.private_data_root))
    uvicorn.run(
        create_app(settings, catalog),
        host=settings.bind_host,
        port=settings.bind_port,
        access_log=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
