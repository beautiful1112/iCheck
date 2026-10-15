from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .config import get_settings


MAX_SANDBOX_RESPONSE_BYTES = 10_000_000
POTENTIAL_SECRET_LITERAL = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{16,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"authorization\s*[:=]\s*['\"]?(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{8,})"
)


class SandboxUnavailable(RuntimeError):
    pass


class SandboxRejected(ValueError):
    pass


class SandboxExecutor(Protocol):
    def validate(
        self,
        implementation: dict[str, Any],
        tests: list[dict[str, Any]],
        output_kinds: list[str],
    ) -> dict[str, Any]: ...

    def transform(
        self,
        implementation: dict[str, Any],
        records: Any,
        configuration: dict[str, Any],
        output_kinds: list[str],
    ) -> list[dict[str, Any]]: ...


def validate_sandbox_implementation(implementation: dict[str, Any]) -> None:
    if set(implementation) != {"runtime", "adapter", "entrypoint", "source"}:
        raise SandboxRejected(
            "python_sandbox_v1 implementation requires exactly runtime, adapter, "
            "entrypoint, and source"
        )
    if implementation.get("runtime") != "python_sandbox_v1":
        raise SandboxRejected("Unsupported sandbox runtime")
    if implementation.get("adapter") not in {
        "http_json_sandbox",
        "ssh_command_sandbox",
    }:
        raise SandboxRejected(
            "python_sandbox_v1 supports only trusted JSON acquisition adapters"
        )
    if implementation.get("entrypoint") != "transform":
        raise SandboxRejected("Sandbox entrypoint must be transform")
    source = implementation.get("source")
    if not isinstance(source, str) or not source.strip():
        raise SandboxRejected("Sandbox source must be a non-empty string")
    if len(source.encode("utf-8")) > 50_000:
        raise SandboxRejected("Sandbox source exceeds 50000 bytes")
    if POTENTIAL_SECRET_LITERAL.search(source):
        raise SandboxRejected(
            "Sandbox source contains a potential credential literal"
        )


@dataclass(frozen=True)
class BubblewrapSandboxExecutor:
    bwrap_path: str
    python_path: str
    timeout_seconds: int = 5
    harness_path: str = str(Path(__file__).with_name("sandbox_harness.py"))

    def _command(self) -> list[str]:
        return [
            self.bwrap_path,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/sandbox",
            "--ro-bind",
            self.harness_path,
            "/sandbox/runner.py",
            "--chdir",
            "/tmp",
            self.python_path,
            "-I",
            "-S",
            "-B",
            "/sandbox/runner.py",
        ]

    def _invoke(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not os.path.isfile(self.bwrap_path) or not os.access(
            self.bwrap_path, os.X_OK
        ):
            raise SandboxUnavailable("Bubblewrap executable is unavailable")
        if not os.path.isfile(self.python_path) or not os.access(
            self.python_path, os.X_OK
        ):
            raise SandboxUnavailable("Sandbox Python executable is unavailable")
        if not os.path.isfile(self.harness_path):
            raise SandboxUnavailable("Sandbox harness is unavailable")
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > 2_000_000:
            raise SandboxRejected("Sandbox request exceeds 2000000 bytes")
        try:
            completed = subprocess.run(
                self._command(),
                input=encoded,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxRejected("Sandbox execution timed out") from exc
        if len(completed.stdout) > MAX_SANDBOX_RESPONSE_BYTES:
            raise SandboxRejected("Sandbox response exceeded 10000000 bytes")
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode(
                "utf-8", errors="replace"
            ).strip()[:500]
            suffix = f": {diagnostic}" if diagnostic else ""
            raise SandboxUnavailable(
                f"Sandbox isolation failed with exit code "
                f"{completed.returncode}{suffix}"
            )
        try:
            result = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxUnavailable("Sandbox returned an invalid response") from exc
        if not isinstance(result, dict):
            raise SandboxUnavailable("Sandbox returned an invalid response")
        if result.get("ok") is not True:
            error = result.get("error")
            if not isinstance(error, str) or not error:
                error = "Sandbox rejected the generated implementation"
            raise SandboxRejected(error[:2000])
        return result

    @staticmethod
    def _base_payload(
        implementation: dict[str, Any], output_kinds: list[str]
    ) -> dict[str, Any]:
        validate_sandbox_implementation(implementation)
        return {
            "source": implementation["source"],
            "entrypoint": implementation["entrypoint"],
            "output_kinds": output_kinds,
        }

    def validate(
        self,
        implementation: dict[str, Any],
        tests: list[dict[str, Any]],
        output_kinds: list[str],
    ) -> dict[str, Any]:
        result = self._invoke(
            {
                **self._base_payload(implementation, output_kinds),
                "operation": "validate",
                "tests": tests,
            }
        )
        return {
            "runtime": "python_sandbox_v1",
            "isolation": "bubblewrap",
            "network": "denied",
            "tests": result["tests"],
        }

    def transform(
        self,
        implementation: dict[str, Any],
        records: Any,
        configuration: dict[str, Any],
        output_kinds: list[str],
    ) -> list[dict[str, Any]]:
        result = self._invoke(
            {
                **self._base_payload(implementation, output_kinds),
                "operation": "transform",
                "records": records,
                "configuration": configuration,
            }
        )
        output = result.get("output")
        if not isinstance(output, list):
            raise SandboxUnavailable("Sandbox output is invalid")
        return output


@dataclass(frozen=True)
class HardenedProcessSandboxExecutor:
    """Unprivileged child isolated by Landlock, seccomp, rlimits, and AST policy."""

    python_path: str
    timeout_seconds: int = 5
    harness_path: str = str(Path(__file__).with_name("sandbox_harness.py"))
    start_new_session: bool = True

    def _invoke(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not os.path.isfile(self.python_path) or not os.access(
            self.python_path, os.X_OK
        ):
            raise SandboxUnavailable("Sandbox Python executable is unavailable")
        if not os.path.isfile(self.harness_path):
            raise SandboxUnavailable("Sandbox harness is unavailable")
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > 2_000_000:
            raise SandboxRejected("Sandbox request exceeds 2000000 bytes")
        command = [
            self.python_path,
            "-I",
            "-S",
            "-B",
            self.harness_path,
        ]
        try:
            with tempfile.TemporaryDirectory(prefix="icheck-sandbox-") as workdir:
                completed = subprocess.run(
                    command,
                    input=encoded,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=workdir,
                    env={"PYTHONDONTWRITEBYTECODE": "1"},
                    start_new_session=self.start_new_session,
                    timeout=self.timeout_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise SandboxRejected("Sandbox execution timed out") from exc
        if len(completed.stdout) > MAX_SANDBOX_RESPONSE_BYTES:
            raise SandboxRejected("Sandbox response exceeded 10000000 bytes")
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode(
                "utf-8", errors="replace"
            ).strip()[:500]
            suffix = f": {diagnostic}" if diagnostic else ""
            raise SandboxUnavailable(
                f"Sandbox process failed with exit code "
                f"{completed.returncode}{suffix}"
            )
        try:
            result = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxUnavailable("Sandbox returned an invalid response") from exc
        if not isinstance(result, dict):
            raise SandboxUnavailable("Sandbox returned an invalid response")
        if result.get("ok") is not True:
            error = result.get("error")
            if not isinstance(error, str) or not error:
                error = "Sandbox rejected the generated implementation"
            raise SandboxRejected(error[:2000])
        return result

    @staticmethod
    def _base_payload(
        implementation: dict[str, Any], output_kinds: list[str]
    ) -> dict[str, Any]:
        validate_sandbox_implementation(implementation)
        return {
            "source": implementation["source"],
            "entrypoint": implementation["entrypoint"],
            "output_kinds": output_kinds,
        }

    def validate(
        self,
        implementation: dict[str, Any],
        tests: list[dict[str, Any]],
        output_kinds: list[str],
    ) -> dict[str, Any]:
        result = self._invoke(
            {
                **self._base_payload(implementation, output_kinds),
                "operation": "validate",
                "tests": tests,
            }
        )
        return {
            "runtime": "python_sandbox_v1",
            "isolation": "landlock_seccomp_process",
            "network": "denied",
            "tests": result["tests"],
        }

    def transform(
        self,
        implementation: dict[str, Any],
        records: Any,
        configuration: dict[str, Any],
        output_kinds: list[str],
    ) -> list[dict[str, Any]]:
        result = self._invoke(
            {
                **self._base_payload(implementation, output_kinds),
                "operation": "transform",
                "records": records,
                "configuration": configuration,
            }
        )
        output = result.get("output")
        if not isinstance(output, list):
            raise SandboxUnavailable("Sandbox output is invalid")
        return output

    def isolation_probe(self) -> dict[str, Any]:
        return self._invoke({"operation": "isolation_probe"})


def execute_extension_tool(source: str, readings: list, arguments: dict, *, executor=None) -> dict:
    """Execute generated result-processing code behind the existing kernel sandbox."""
    implementation = {"runtime": "python_sandbox_v1", "adapter": "ssh_command_sandbox",
                      "entrypoint": "transform", "source": source}
    validate_sandbox_implementation(implementation)
    runner = executor or default_sandbox_executor()
    if not isinstance(runner, (HardenedProcessSandboxExecutor, BubblewrapSandboxExecutor)):
        raise SandboxUnavailable("Executable extensions require the native kernel sandbox")
    result = runner._invoke({"operation": "tool", "source": source, "entrypoint": "transform",
        "output_kinds": ["mcp_tool_result"], "records": readings, "configuration": arguments})
    if not isinstance(result.get("output"), dict):
        raise SandboxUnavailable("Extension returned an invalid structured result")
    return result["output"]


def default_sandbox_executor() -> SandboxExecutor:
    settings = get_settings()
    if not settings.sandbox_enabled:
        raise SandboxUnavailable(
            "Generated-code sandbox is disabled; set ICHECK_SANDBOX_ENABLED=true"
        )
    if settings.sandbox_backend == "bubblewrap":
        return BubblewrapSandboxExecutor(
            bwrap_path=settings.sandbox_bwrap_path,
            python_path=settings.sandbox_python_path,
            timeout_seconds=settings.sandbox_timeout_seconds,
        )
    return HardenedProcessSandboxExecutor(
        python_path=settings.sandbox_python_path,
        timeout_seconds=settings.sandbox_timeout_seconds,
    )
