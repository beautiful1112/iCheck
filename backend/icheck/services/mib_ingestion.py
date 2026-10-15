from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


MAX_MIB_BYTES = 1_000_000
MAX_MIB_SYMBOLS = 500
MAX_OID_ARCS = 128

MODULE_PATTERN = re.compile(
    r"(?m)^[ \t]*([A-Za-z][A-Za-z0-9-]*)[ \t]+DEFINITIONS[ \t]*"
    r"::=[ \t]*BEGIN\b"
)
ASSIGNMENT_PATTERN = re.compile(
    r"(?ms)^[ \t]*([A-Za-z][A-Za-z0-9-]*)[ \t]+"
    r"(OBJECT-TYPE|OBJECT[ \t]+IDENTIFIER|MODULE-IDENTITY|OBJECT-IDENTITY|"
    r"NOTIFICATION-TYPE)\b(.*?)::=[ \t]*\{[ \t\r\n]*"
    r"([^{}]{1,2000})[ \t\r\n]*\}"
)
SYNTAX_PATTERN = re.compile(
    r"(?ms)\bSYNTAX[ \t]+(.+?)(?=^[ \t]*(?:MAX-ACCESS|ACCESS|STATUS|"
    r"DESCRIPTION|REFERENCE|UNITS|INDEX|AUGMENTS|DEFVAL)\b)"
)
ACCESS_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:MAX-ACCESS|ACCESS)[ \t]+([A-Za-z-]+)\b"
)
INDEX_PATTERN = re.compile(r"(?ms)\bINDEX[ \t]*\{([^{}]{1,1000})\}")
IMPORT_PATTERN = re.compile(r"(?m)\bFROM[ \t]+([A-Za-z][A-Za-z0-9-]*)\b")
ARC_PATTERN = re.compile(
    r"^(?:(?P<name>[A-Za-z][A-Za-z0-9-]*)(?:\((?P<named>\d+)\))?"
    r"|(?P<number>\d+))$"
)
SYMBOL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


ROOT_OIDS: dict[str, tuple[int, ...]] = {
    "ccitt": (0,),
    "iso": (1,),
    "joint-iso-ccitt": (2,),
    "org": (1, 3),
    "dod": (1, 3, 6),
    "internet": (1, 3, 6, 1),
    "directory": (1, 3, 6, 1, 1),
    "mgmt": (1, 3, 6, 1, 2),
    "mib-2": (1, 3, 6, 1, 2, 1),
    "transmission": (1, 3, 6, 1, 2, 1, 10),
    "experimental": (1, 3, 6, 1, 3),
    "private": (1, 3, 6, 1, 4),
    "enterprises": (1, 3, 6, 1, 4, 1),
    "security": (1, 3, 6, 1, 5),
    "snmpV2": (1, 3, 6, 1, 6),
    "snmpModules": (1, 3, 6, 1, 6, 3),
}


@dataclass(frozen=True)
class MIBCollectorInput:
    sample_document: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class _Assignment:
    name: str
    kind: str
    oid_expression: str
    syntax: str | None
    access: str | None
    index_symbols: tuple[str, ...]


def _strip_comments(value: str) -> str:
    result: list[str] = []
    quoted = False
    for line in value.splitlines(keepends=True):
        index = 0
        while index < len(line):
            character = line[index]
            if character == '"':
                if quoted and index + 1 < len(line) and line[index + 1] == '"':
                    result.extend(['"', '"'])
                    index += 2
                    continue
                quoted = not quoted
            if not quoted and line[index : index + 2] == "--":
                if line.endswith("\n"):
                    result.append("\n")
                break
            result.append(character)
            index += 1
    return "".join(result)


def _normalized_syntax(metadata: str) -> str | None:
    match = SYNTAX_PATTERN.search(metadata)
    if match is None:
        return None
    value = " ".join(match.group(1).split())
    if not value:
        return None
    return value[:256]


def _index_symbols(metadata: str) -> tuple[str, ...]:
    match = INDEX_PATTERN.search(metadata)
    if match is None:
        return ()
    symbols: list[str] = []
    for value in re.split(r"[\s,]+", match.group(1).strip()):
        normalized = value.strip()
        if normalized and SYMBOL_PATTERN.fullmatch(normalized):
            symbols.append(normalized)
        if len(symbols) == 16:
            break
    return tuple(dict.fromkeys(symbols))


def _assignments(document: str) -> list[_Assignment]:
    result: list[_Assignment] = []
    seen: set[str] = set()
    for match in ASSIGNMENT_PATTERN.finditer(document):
        name = match.group(1)
        if name in seen:
            raise ValueError(f"MIB contains duplicate symbol {name!r}")
        seen.add(name)
        raw_kind = " ".join(match.group(2).split()).lower()
        kind = raw_kind.replace("-", "_").replace(" ", "_")
        metadata = match.group(3)
        access_match = ACCESS_PATTERN.search(metadata)
        result.append(
            _Assignment(
                name=name,
                kind=kind,
                oid_expression=" ".join(match.group(4).replace(",", " ").split()),
                syntax=(
                    _normalized_syntax(metadata)
                    if kind == "object_type"
                    else None
                ),
                access=(
                    access_match.group(1).lower()
                    if access_match is not None
                    else None
                ),
                index_symbols=(
                    _index_symbols(metadata) if kind == "object_type" else ()
                ),
            )
        )
        if len(result) > MAX_MIB_SYMBOLS:
            raise ValueError(
                f"MIB contains more than {MAX_MIB_SYMBOLS} supported symbols"
            )
    return result


def _resolve_expression(
    expression: str,
    resolved: dict[str, tuple[int, ...]],
) -> tuple[int, ...] | None:
    tokens = expression.split()
    if not tokens or len(tokens) > MAX_OID_ARCS:
        return None
    current: tuple[int, ...] | None = None
    for token in tokens:
        match = ARC_PATTERN.fullmatch(token)
        if match is None:
            return None
        name = match.group("name")
        named_number = match.group("named")
        number = match.group("number")
        if number is not None:
            arc = int(number)
            current = (arc,) if current is None else (*current, arc)
            continue
        assert name is not None
        known = resolved.get(name)
        if named_number is None:
            if current is not None or known is None:
                return None
            current = known
            continue
        arc = int(named_number)
        if current is None:
            if known is None or known[-1] != arc:
                return None
            current = known
        else:
            current = (*current, arc)
    if current is None or len(current) > MAX_OID_ARCS:
        return None
    if any(arc < 0 or arc > 4_294_967_295 for arc in current):
        return None
    return current


def extract_mib_collector_input(value: str) -> MIBCollectorInput:
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_MIB_BYTES:
        raise ValueError(f"MIB document exceeds {MAX_MIB_BYTES} bytes")
    if "\x00" in value or any(
        ord(character) < 32 and character not in "\t\r\n"
        for character in value
    ):
        raise ValueError("MIB document contains unsupported control characters")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    document = _strip_comments(normalized)
    modules = MODULE_PATTERN.findall(document)
    if len(modules) != 1:
        raise ValueError("MIB input must contain exactly one SMI module")
    if re.search(r"(?m)^[ \t]*END[ \t]*$", document) is None:
        raise ValueError("MIB module must terminate with END")
    assignments = _assignments(document)
    if not assignments:
        raise ValueError("MIB contains no supported OID assignments")

    resolved = dict(ROOT_OIDS)
    pending = {item.name: item for item in assignments}
    progress = True
    while pending and progress:
        progress = False
        for name, item in list(pending.items()):
            oid = _resolve_expression(item.oid_expression, resolved)
            if oid is None:
                continue
            resolved[name] = oid
            del pending[name]
            progress = True

    symbols: list[dict[str, Any]] = []
    for item in assignments:
        oid = resolved.get(item.name)
        if oid is None or item.kind == "notification_type":
            continue
        symbols.append(
            {
                "name": item.name,
                "kind": item.kind,
                "oid": ".".join(str(arc) for arc in oid),
                "syntax": item.syntax,
                "access": item.access,
                "index_symbols": list(item.index_symbols),
            }
        )
    if not symbols:
        raise ValueError(
            "MIB has no locally resolvable object identifiers; include its "
            "numeric enterprise root or required parent MIB"
        )
    symbols.sort(key=lambda item: tuple(int(arc) for arc in item["oid"].split(".")))
    document_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    imports = sorted(set(IMPORT_PATTERN.findall(document)))[:100]
    sample_document = {
        "module_name": modules[0],
        "symbols": symbols,
    }
    provenance = {
        "module_name": modules[0],
        "document_sha256": document_sha256,
        "parser": "icheck_smi_subset_v1",
        "resolved_symbol_count": len(symbols),
        "unresolved_symbol_count": len(pending),
        "imported_modules": imports,
    }
    return MIBCollectorInput(
        sample_document=sample_document,
        provenance=provenance,
    )
