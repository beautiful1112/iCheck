"""Secret-free exporter module catalog and enrollment validation.

The native host's root-provisioned module catalog is authoritative. Hosts without
that catalog can enroll the portable system/if_mib defaults only; their Collector
still checks its own installed catalog before using a managed credential.
"""
import os
import re
from pathlib import Path

from .managed_snmp import module_document

ADAPTER_NAMES = frozenset({"snmp_exporter", "snmp_topology"})
IDENTITY_MODULE = "icheck_identity"


def module_catalog() -> list[str]:
    path = Path(os.environ.get("ICHECK_MANAGED_SNMP_MODULES_FILE",
        "/etc/icheck-workers/snmp-runtime/modules.yml"))
    if not path.exists():
        return ["if_mib", "system"]
    return sorted(module_document()["modules"])


def validate_modules(value, *, available=None) -> list[str]:
    if (not isinstance(value, list) or not 1 <= len(value) <= 8
        or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) for name in value)
        or len(value) != len(set(value))):
        raise ValueError("SNMP modules must be 1 to 8 distinct bounded module names")
    if any(name in ADAPTER_NAMES for name in value):
        raise ValueError("snmp_exporter and snmp_topology are collector adapters, not SNMP modules. "
            "Select installed modules such as if_mib (interfaces) or system (identity).")
    catalog = set(module_catalog() if available is None else available)
    unknown = [name for name in value if name not in catalog]
    if unknown:
        raise ValueError("Unknown installed SNMP module(s): " + ", ".join(unknown)
            + ". Select modules from the SNMP module catalog.")
    return list(value)


def safe_sysname(value) -> str | None:
    # Device-provided strings are untrusted data, never commands or HTML.
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value
