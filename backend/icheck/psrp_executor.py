from __future__ import annotations

import importlib
import importlib.util
import ipaddress
import json
import math
import multiprocessing
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .collectors.psrp_cim import CIM_OPERATIONS


PSRP_AUTH_MODES = frozenset({"basic", "ntlm"})
_CONFIGURATION_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class PSRPDependencyUnavailable(RuntimeError):
    """The optional Windows transport dependency is not installed."""


@dataclass(frozen=True)
class _PSRPRequest:
    host: str
    port: int
    username: str
    password: str
    auth: str
    ca_file: str | None
    configuration_name: str
    script: str
    timeout_seconds: int
    max_response_bytes: int


def _host_allowed(hostname: str, patterns: tuple[str, ...]) -> bool:
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


def _reject_constant(value: str) -> None:
    raise ValueError(f"PSRP/CIM output contains non-finite value {value!r}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("PSRP/CIM output contains duplicate key")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("PSRP/CIM output contains non-finite value")
    return number


def _load_client_factory() -> Callable[..., Any]:
    try:
        module = importlib.import_module("pypsrp.client")
    except ImportError as exc:
        raise PSRPDependencyUnavailable(
            "PSRP/CIM transport requires the optional icheck[windows] dependency"
        ) from exc
    factory = getattr(module, "Client", None)
    if not callable(factory):
        raise PSRPDependencyUnavailable(
            "PSRP/CIM transport could not load pypsrp.client.Client"
        )
    return factory


def _decode_output(
    output: Any,
    max_response_bytes: int,
) -> dict[str, Any] | list[dict[str, Any]]:
    if isinstance(output, str):
        encoded = output.encode("utf-8")
    elif isinstance(output, bytes):
        encoded = output
    else:
        raise RuntimeError("PSRP/CIM transport returned an invalid output type")
    if len(encoded) > max_response_bytes:
        raise ValueError("PSRP/CIM output exceeded max_response_bytes")
    try:
        document = json.loads(
            encoded.decode("utf-8"),
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            object_pairs_hook=_object_without_duplicates,
        )
    except UnicodeDecodeError as exc:
        raise ValueError("PSRP/CIM output must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("PSRP/CIM output must be valid JSON") from exc
    if isinstance(document, dict):
        return document
    if isinstance(document, list) and all(
        isinstance(item, dict) for item in document
    ):
        return document
    raise ValueError("PSRP/CIM output must be an object or an array of objects")


def _execute_request(
    request: _PSRPRequest,
    client_factory: Callable[..., Any] | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    factory = client_factory or _load_client_factory()
    operation_timeout = max(1, request.timeout_seconds - 2)
    read_timeout = max(2, request.timeout_seconds - 1)
    try:
        with factory(
            request.host,
            port=request.port,
            username=request.username,
            password=request.password,
            ssl=True,
            auth=request.auth,
            cert_validation=request.ca_file or True,
            connection_timeout=request.timeout_seconds,
            operation_timeout=operation_timeout,
            read_timeout=read_timeout,
            no_proxy=True,
            reconnection_retries=0,
        ) as client:
            execution = client.execute_ps(
                request.script,
                configuration_name=request.configuration_name,
            )
    except PSRPDependencyUnavailable:
        raise
    except Exception as exc:
        raise RuntimeError(
            "PSRP/CIM TLS connection or execution failed"
        ) from exc
    if not isinstance(execution, tuple) or len(execution) != 3:
        raise RuntimeError("PSRP/CIM transport returned an invalid execution result")
    output, _streams, had_errors = execution
    if had_errors is not False:
        raise RuntimeError("PSRP/CIM remote execution failed")
    return _decode_output(output, request.max_response_bytes)


def _execute_child(connection: Any, request: _PSRPRequest) -> None:
    try:
        connection.send(("ok", _execute_request(request)))
    except PSRPDependencyUnavailable as exc:
        connection.send(("dependency", str(exc)))
    except (RuntimeError, ValueError) as exc:
        connection.send(("error", str(exc)))
    except BaseException:
        connection.send(("error", "PSRP/CIM transport process failed"))
    finally:
        connection.close()


@dataclass(frozen=True)
class PSRPCIMTransportExecutor:
    """Execute fixed CIM templates over certificate-verified WinRM HTTPS."""

    allowed_targets: tuple[str, ...]
    allowed_ports: tuple[int, ...] = (5986,)
    auth: str = "ntlm"
    ca_file: str | None = None
    configuration_name: str = "Microsoft.PowerShell"
    client_factory: Callable[..., Any] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not self.allowed_targets:
            raise ValueError("PSRP/CIM transport requires at least one allowed target")
        if not self.allowed_ports or any(
            not isinstance(port, int) or port < 1 or port > 65535
            for port in self.allowed_ports
        ):
            raise ValueError("PSRP/CIM allowed ports must be between 1 and 65535")
        if self.auth not in PSRP_AUTH_MODES:
            raise ValueError("PSRP/CIM auth must be 'ntlm' or 'basic'")
        if not _CONFIGURATION_NAME.fullmatch(self.configuration_name):
            raise ValueError("PSRP/CIM configuration name is invalid")
        if self.ca_file is not None:
            path = Path(self.ca_file)
            if not path.is_absolute():
                raise ValueError("PSRP/CIM CA file must be an absolute path")
            if not path.is_file():
                raise ValueError("PSRP/CIM CA file does not exist")

    @staticmethod
    def require_dependency() -> None:
        try:
            available = importlib.util.find_spec("pypsrp.client") is not None
        except (ImportError, ModuleNotFoundError):
            available = False
        if not available:
            raise PSRPDependencyUnavailable(
                "PSRP/CIM transport requires the optional icheck[windows] dependency"
            )

    def __call__(
        self,
        *,
        host: str,
        port: int,
        use_ssl: bool,
        credential_profile_ref: str,
        credential: dict[str, str],
        operation: str,
        script: str,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        if use_ssl is not True:
            raise ValueError("PSRP/CIM transport requires WinRM over TLS")
        if not isinstance(host, str) or not _host_allowed(
            host,
            self.allowed_targets,
        ):
            raise ValueError(
                f"PSRP/CIM transport target {host!r} is not allowlisted"
            )
        if port not in self.allowed_ports:
            raise ValueError(f"PSRP/CIM transport port {port!r} is not allowlisted")
        expected_script = CIM_OPERATIONS.get(operation)
        if expected_script is None or script != expected_script:
            raise ValueError("PSRP/CIM transport rejected an unregistered script")
        if not isinstance(credential_profile_ref, str) or not credential_profile_ref:
            raise ValueError(
                "PSRP/CIM transport requires a credential profile reference"
            )
        username = credential.get("username")
        password = credential.get("password")
        if not isinstance(username, str) or not username:
            raise ValueError("PSRP/CIM credential requires a username")
        if not isinstance(password, str) or not password:
            raise ValueError("PSRP/CIM credential requires a password")
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise ValueError("PSRP/CIM timeout must be between 1 and 120 seconds")
        if max_response_bytes < 1 or max_response_bytes > 10_000_000:
            raise ValueError(
                "PSRP/CIM max_response_bytes must be between 1 and 10000000"
            )

        request = _PSRPRequest(
            host=host,
            port=port,
            username=username,
            password=password,
            auth=self.auth,
            ca_file=self.ca_file,
            configuration_name=self.configuration_name,
            script=script,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if self.client_factory is not None:
            return _execute_request(request, self.client_factory)
        return self._execute_isolated(request)

    @staticmethod
    def _execute_isolated(
        request: _PSRPRequest,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        context = multiprocessing.get_context("spawn")
        receive_connection, send_connection = context.Pipe(duplex=False)
        process = context.Process(
            target=_execute_child,
            args=(send_connection, request),
            name="icheck-psrp-cim",
        )
        try:
            process.start()
        except Exception as exc:
            receive_connection.close()
            send_connection.close()
            raise RuntimeError("PSRP/CIM transport process could not start") from exc
        send_connection.close()
        try:
            if not receive_connection.poll(request.timeout_seconds):
                raise TimeoutError
            try:
                status, payload = receive_connection.recv()
            except EOFError as exc:
                raise RuntimeError("PSRP/CIM transport process failed") from exc
        except TimeoutError as exc:
            process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            raise RuntimeError("PSRP/CIM execution timed out") from exc
        finally:
            receive_connection.close()
        process.join(timeout=1)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
        if status == "ok":
            return payload
        if status == "dependency":
            raise PSRPDependencyUnavailable(payload)
        raise RuntimeError(payload)
