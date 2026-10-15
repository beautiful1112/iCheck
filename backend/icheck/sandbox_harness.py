"""Stdlib-only generated transformer harness.

This file is executed inside an OS sandbox. Keep it free of project imports so
the Bubblewrap filesystem can expose only the Python standard library and this
single read-only file.
"""

from __future__ import annotations

import ast
import ctypes
import errno
import hashlib
import json
import os
import platform
import resource
import signal
import socket
import sys
import time
from typing import Any


MAX_INPUT_BYTES = 2_000_000
MAX_OUTPUT_BYTES = 10_000_000
MAX_SOURCE_BYTES = 50_000
MAX_AST_NODES = 2_000
MAX_ENVELOPES = 2_000
MAX_TESTS = 100

SAFE_BUILTINS = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "float": float,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}
SAFE_METHODS = {
    "append",
    "copy",
    "count",
    "endswith",
    "extend",
    "get",
    "index",
    "items",
    "join",
    "keys",
    "lower",
    "replace",
    "split",
    "startswith",
    "strip",
    "upper",
    "values",
}
SENSITIVE_IDENTIFIERS = {
    "api_key",
    "apikey",
    "authorization",
    "community",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}
DENIED_NODES = (
    ast.AsyncFunctionDef,
    ast.Await,
    ast.ClassDef,
    ast.Delete,
    ast.Global,
    ast.Import,
    ast.ImportFrom,
    ast.Lambda,
    ast.Nonlocal,
    ast.Raise,
    ast.Try,
    ast.While,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)
ALLOWED_ENVELOPE_KEYS = {
    "idempotency_key",
    "kind",
    "observed_at",
    "payload",
    "source",
    "subject",
    "type",
}

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_ACCESS_FS_BASE = (1 << 13) - 1


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


_LIBC = ctypes.CDLL(None, use_errno=True)
_DENIED_SYSCALLS_X86_64 = {
    2,  # open
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 62, 85, 101, 155, 161, 165, 166,
    234, 257, 258, 259, 263, 264, 265, 266, 268,
    272, 288, 298, 299, 304, 307, 308, 310, 311,
    313, 316, 317, 319, 321, 322, 323,
    434, 435, 438,
}


class HarnessError(ValueError):
    pass


def _prctl(option: int, argument: Any) -> None:
    result = _LIBC.prctl(option, argument, 0, 0, 0)
    if result != 0:
        code = ctypes.get_errno()
        raise HarnessError(f"kernel sandbox prctl failed with errno {code}")


def _apply_landlock() -> int:
    if platform.machine() not in {"x86_64", "amd64"}:
        raise HarnessError("kernel sandbox supports x86_64 only")
    abi = _LIBC.syscall(444, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 1:
        code = ctypes.get_errno()
        raise HarnessError(f"Landlock is unavailable (errno {code})")
    handled = LANDLOCK_ACCESS_FS_BASE
    if abi >= 2:
        handled |= 1 << 13  # REFER
    if abi >= 3:
        handled |= 1 << 14  # TRUNCATE
    if abi >= 5:
        handled |= 1 << 15  # IOCTL_DEV
    attributes = _LandlockRulesetAttr(handled_access_fs=handled)
    ruleset_fd = _LIBC.syscall(
        444,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
        0,
    )
    if ruleset_fd < 0:
        code = ctypes.get_errno()
        raise HarnessError(f"Landlock ruleset creation failed (errno {code})")
    try:
        _prctl(PR_SET_NO_NEW_PRIVS, 1)
        if _LIBC.syscall(446, ruleset_fd, 0) != 0:
            code = ctypes.get_errno()
            raise HarnessError(f"Landlock restriction failed (errno {code})")
    finally:
        os.close(ruleset_fd)
    return int(abi)


def _apply_seccomp() -> None:
    instructions = [_SockFilter(BPF_LD_W_ABS, 0, 0, 0)]
    denied = SECCOMP_RET_ERRNO | errno.EPERM
    for syscall_number in sorted(_DENIED_SYSCALLS_X86_64):
        instructions.append(
            _SockFilter(BPF_JMP_JEQ_K, 0, 1, syscall_number)
        )
        instructions.append(_SockFilter(BPF_RET_K, 0, 0, denied))
    instructions.append(_SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    array_type = _SockFilter * len(instructions)
    filters = array_type(*instructions)
    program = _SockFprog(len=len(instructions), filter=filters)
    _prctl(PR_SET_NO_NEW_PRIVS, 1)
    result = _LIBC.prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        ctypes.byref(program),
        0,
        0,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise HarnessError(f"seccomp filter failed (errno {code})")


def _apply_kernel_sandbox() -> dict[str, Any]:
    abi = _apply_landlock()
    _apply_seccomp()
    return {"landlock_abi": abi, "seccomp": True}


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    except (OSError, ValueError):
        pass
    signal.alarm(4)


def _safe_name(value: str, label: str) -> None:
    if not value or value.startswith("_") or "__" in value:
        raise HarnessError(f"{label} contains a reserved name")
    normalized = value.lower()
    if normalized in SENSITIVE_IDENTIFIERS or any(
        normalized.endswith(f"_{suffix}")
        for suffix in SENSITIVE_IDENTIFIERS
    ):
        raise HarnessError(f"{label} may not handle credential material")


def _compile(source: str, entrypoint: str):
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise HarnessError("source exceeds 50000 bytes")
    if entrypoint != "transform":
        raise HarnessError("entrypoint must be transform")
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as exc:
        raise HarnessError(
            f"source syntax error at line {exc.lineno or 0}"
        ) from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_AST_NODES:
        raise HarnessError("source exceeds the AST node budget")
    functions = {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    if any(not isinstance(node, ast.FunctionDef) for node in tree.body):
        raise HarnessError("source may contain only function definitions")
    if entrypoint not in functions:
        raise HarnessError("source must define transform(records, configuration)")
    for node in nodes:
        if isinstance(node, DENIED_NODES):
            raise HarnessError(
                f"source contains forbidden syntax: {type(node).__name__}"
            )
        if isinstance(node, ast.FunctionDef):
            _safe_name(node.name, "function")
            if node.decorator_list:
                raise HarnessError("function decorators are forbidden")
            if node.name in SAFE_BUILTINS:
                raise HarnessError("functions cannot shadow safe builtins")
            if node.args.vararg or node.args.kwarg or node.args.kwonlyargs:
                raise HarnessError("variadic and keyword-only arguments are forbidden")
            for argument in node.args.args:
                _safe_name(argument.arg, "argument")
        if isinstance(node, ast.Name):
            _safe_name(node.id, "identifier")
            if isinstance(node.ctx, ast.Store) and node.id in SAFE_BUILTINS:
                raise HarnessError("safe builtins cannot be reassigned")
        if isinstance(node, ast.Attribute):
            if node.attr not in SAFE_METHODS:
                raise HarnessError(f"method {node.attr!r} is not allowed")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in SAFE_BUILTINS and node.func.id not in functions:
                    raise HarnessError(f"call to {node.func.id!r} is not allowed")
            elif not isinstance(node.func, ast.Attribute):
                raise HarnessError("indirect calls are forbidden")
    entry_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == entrypoint
    )
    if len(entry_node.args.args) != 2:
        raise HarnessError("transform must accept records and configuration")
    code = compile(tree, "<generated-transformer>", "exec")
    _apply_kernel_sandbox()
    namespace: dict[str, Any] = {"__builtins__": SAFE_BUILTINS}
    exec(code, namespace, namespace)
    return namespace[entrypoint]


def _bounded_string(value: Any, name: str, maximum: int, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise HarnessError(f"envelope {name} must be a string up to {maximum} chars")


def _validate_envelopes(value: Any, output_kinds: set[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise HarnessError("transform must return a list of envelopes")
    if len(value) > MAX_ENVELOPES:
        raise HarnessError("transform exceeded 2000 envelopes")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise HarnessError(f"envelope {index} must be an object")
        unexpected = set(item) - ALLOWED_ENVELOPE_KEYS
        if unexpected:
            raise HarnessError(f"envelope {index} contains unsupported fields")
        if item.get("kind") not in output_kinds:
            raise HarnessError(f"envelope {index} kind is not declared")
        _bounded_string(item.get("type"), "type", 128)
        _bounded_string(item.get("source"), "source", 255)
        _bounded_string(item.get("subject"), "subject", 512, optional=True)
        _bounded_string(
            item.get("idempotency_key"),
            "idempotency_key",
            512,
            optional=True,
        )
        _bounded_string(item.get("observed_at"), "observed_at", 64, optional=True)
        if not isinstance(item.get("payload"), dict):
            raise HarnessError(f"envelope {index} payload must be an object")
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise HarnessError("transform output exceeds 10000000 bytes")
    return value


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _execute(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("operation") == "isolation_probe":
        status = _apply_kernel_sandbox()
        file_denied = False
        network_denied = False
        process_denied = False
        try:
            open("/etc/passwd", encoding="utf-8")
        except OSError:
            file_denied = True
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            network_denied = True
        try:
            os.fork()
        except OSError:
            process_denied = True
        return {
            "ok": file_denied and network_denied and process_denied,
            "filesystem_denied": file_denied,
            "network_denied": network_denied,
            "process_creation_denied": process_denied,
            **status,
        }
    source = request.get("source")
    entrypoint = request.get("entrypoint")
    output_kinds = request.get("output_kinds")
    if not isinstance(source, str):
        raise HarnessError("source must be a string")
    if not isinstance(entrypoint, str):
        raise HarnessError("entrypoint must be a string")
    if (
        not isinstance(output_kinds, list)
        or not output_kinds
        or any(not isinstance(item, str) for item in output_kinds)
    ):
        raise HarnessError("output_kinds must be a non-empty string list")
    transform = _compile(source, entrypoint)
    operation = request.get("operation")
    if operation == "tool":
        configuration = request.get("configuration", {})
        if not isinstance(configuration, dict):
            raise HarnessError("tool arguments must be an object")
        output = transform(request.get("records"), configuration)
        if not isinstance(output, dict):
            raise HarnessError("tool implementation must return an object")
        if len(json.dumps(output, allow_nan=False).encode()) > 128_000:
            raise HarnessError("tool result exceeds 128000 bytes")
        return {"ok": True, "output": output}
    if operation == "transform":
        configuration = request.get("configuration", {})
        if not isinstance(configuration, dict):
            raise HarnessError("configuration must be an object")
        output = _validate_envelopes(
            transform(request.get("records"), configuration),
            set(output_kinds),
        )
        return {"ok": True, "output": output, "output_sha256": _hash(output)}
    if operation != "validate":
        raise HarnessError("unsupported sandbox operation")
    tests = request.get("tests")
    if not isinstance(tests, list) or not tests or len(tests) > MAX_TESTS:
        raise HarnessError("sandbox implementations require 1 to 100 tests")
    reports = []
    for index, item in enumerate(tests):
        if not isinstance(item, dict):
            raise HarnessError(f"test {index} must be an object")
        name = item.get("name")
        expected = item.get("expected")
        configuration = item.get("configuration", {})
        if not isinstance(name, str) or not name or len(name) > 255:
            raise HarnessError(f"test {index} has an invalid name")
        if "expected" not in item:
            raise HarnessError(f"test {name!r} must declare expected output")
        if not isinstance(configuration, dict):
            raise HarnessError(f"test {name!r} configuration must be an object")
        started = time.monotonic()
        output = _validate_envelopes(
            transform(item.get("fixture"), configuration),
            set(output_kinds),
        )
        if output != expected:
            raise HarnessError(f"test {name!r} output did not match expected")
        reports.append(
            {
                "name": name,
                "passed": True,
                "output_count": len(output),
                "output_sha256": _hash(output),
                "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
            }
        )
    return {"ok": True, "tests": reports}


def main() -> int:
    _limits()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        result = {"ok": False, "error": "sandbox request exceeds 2000000 bytes"}
    else:
        try:
            request = json.loads(raw.decode("utf-8"))
            if not isinstance(request, dict):
                raise HarnessError("sandbox request must be an object")
            result = _execute(request)
        except BaseException as exc:
            result = {
                "ok": False,
                "error": str(exc)[:2000] or type(exc).__name__,
                "error_type": type(exc).__name__,
            }
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_OUTPUT_BYTES:
        encoded = b'{"ok":false,"error":"sandbox response exceeded limit"}'
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
