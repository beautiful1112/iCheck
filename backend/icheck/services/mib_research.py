"""Resolve missing MIB families from public vendor and upstream source repositories.

Documents are untrusted compiler inputs, never Python or shell. Installed/uploaded
modules win; downloads are retained only in the versioned authoring recipe.
"""
import hashlib
import re
import time

from ..config import get_settings
from ..public_research_http import ResearchUnavailable, fetch
from ..snmp_generator import MODULE
from .research import now

SOURCE = "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/"
STANDARD_SOURCES = {
    "RFC1155-SMI": "https://raw.githubusercontent.com/net-snmp/net-snmp/v5.9/mibs/RFC1155-SMI.txt",
    "RFC-1212": "https://raw.githubusercontent.com/librenms/librenms/master/mibs/RFC-1212",
    "RFC-1215": "https://raw.githubusercontent.com/net-snmp/net-snmp/v5.9/mibs/RFC-1215.txt",
}
LEGACY_MODULES = {"RFC1213-MIB", "RFC1155-SMI", "RFC-1212", "RFC-1215"}
MODULE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")


def imports(document):
    # Strip quoted descriptions and line comments before identifying imports.
    text = re.sub(r'"(?:[^"\\]|\\.)*"', '""', document, flags=re.S)
    text = re.sub(r"--[^\n]*", "", text)
    block = re.search(r"\bIMPORTS\b(.*?);", text, re.S)
    return list(dict.fromkeys(re.findall(r"\bFROM\s+([A-Za-z][A-Za-z0-9-]*)", block.group(1)))) if block else []


def complete_bundle(modules, existing, *, transport=None):
    if not isinstance(modules, list) or not 1 <= len(modules) <= 16 or any(not MODULE_NAME.fullmatch(m) for m in modules):
        raise ValueError("Select 1 to 16 valid MIB module names")
    sources = {}
    for document in existing:
        names = MODULE.findall(document)
        if len(names) != 1:
            raise ValueError("A MIB source must declare exactly one module")
        if names[0] in sources and sources[names[0]] != document:
            raise ValueError("Conflicting MIB module sources")
        sources[names[0]] = document
    needed, visited, provenance = list(modules), set(), []
    deadline = time.monotonic() + 60
    while needed:
        name = needed.pop(0)
        if name in visited:
            continue
        visited.add(name)
        if len(visited) > 32:
            raise ValueError("MIB dependency family exceeds 32 modules")
        if name not in sources:
            if not get_settings().research_enabled:
                raise ValueError("Missing MIB dependency; enable internet research or upload the MIB family")
            remaining = min(get_settings().research_timeout_seconds, deadline - time.monotonic())
            if remaining <= 0:
                raise ResearchUnavailable("MIB research exceeded its time budget")
            prefix = SOURCE.replace("/v2/", "/v1/") if name in LEGACY_MODULES else SOURCE
            try:
                request = transport or fetch
                try:
                    url, _, body = request(STANDARD_SOURCES.get(name, prefix + name + ".my"),
                                           timeout=remaining, maximum=1_000_000)
                except ResearchUnavailable as exc:
                    # Some SMIv2 modules import dependencies published only in
                    # Cisco's SMIv1 directory. Probe that one known alternative
                    # only on an exact 404, not on auth, timeout or TLS failures.
                    if exc.status_code != 404 or prefix != SOURCE:
                        raise
                    remaining = min(get_settings().research_timeout_seconds, deadline - time.monotonic())
                    if remaining <= 0:
                        raise ResearchUnavailable("MIB research exceeded its time budget") from None
                    url, _, body = request(SOURCE.replace("/v2/", "/v1/") + name + ".my",
                                           timeout=remaining, maximum=1_000_000)
            except ResearchUnavailable:
                raise ResearchUnavailable(f"Public source for MIB {name} is unavailable; provide that dependency or retry research") from None
            document = body.decode("utf-8")
            if MODULE.findall(document) != [name] or "\x00" in document:
                raise ValueError("Downloaded MIB does not declare the requested module")
            sources[name] = document
            provenance.append({"module": name, "url": url, "sha256": hashlib.sha256(body).hexdigest(), "retrieved_at": now()})
        needed.extend(imports(sources[name]))
        if sum(len(sources[m].encode()) for m in visited if m in sources) > 4_000_000:
            raise ValueError("MIB dependency family exceeds 4 MB")
    return {"documents": [sources[name] for name in sorted(visited)], "sources": provenance}
