"""Append-only module installation, independent of target activation.

The generic file transaction is testable in a private catalog. The native CLI
requires root-owned installed code and writes one fixed root-provisioned catalog;
it cannot accept an output path, auth profiles, service commands or target IPs.
No sudo grant or root service is provisioned by importing this module.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

import yaml

from .managed_snmp import trusted_file
from .snmp_generator import dry_run_modules, load_yaml, validate_compiled

CATALOG = Path("/etc/icheck-workers/snmp-runtime/modules.yml")
EXPORTER = Path("/opt/icheck/bin/snmp_exporter")
MAX_CATALOG = 20_000_000


def _read_catalog(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_CATALOG:
            raise ValueError("SNMP catalog must be a bounded regular single-link file")
        encoded = handle.read(MAX_CATALOG + 1)
    document = load_yaml(encoded, maximum=MAX_CATALOG)
    if not isinstance(document, dict) or set(document) != {"modules"} or not isinstance(document["modules"], dict):
        raise ValueError("SNMP catalog must contain modules only")
    return document, encoded, info


def install_module(candidate, *, catalog: Path, exporter: Path, expected_catalog_sha256: str,
        confirm: bool = False, verify=dry_run_modules):
    """CAS, native parser validation, atomic append; never overwrite a module."""
    module = validate_compiled(candidate)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_catalog_sha256):
        raise ValueError("Expected SNMP catalog digest is required")
    lock = catalog.parent / ".modules.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError("SNMP catalog lock custody is unsafe")
        try: fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("SNMP module installation is already in progress") from None
        document, original, old_info = _read_catalog(catalog)
        current_hash = hashlib.sha256(original).hexdigest()
        if current_hash != expected_catalog_sha256:
            raise ValueError("SNMP catalog changed after preview; review it again")
        name = candidate["module_name"]
        previous = document["modules"].get(name)
        if previous is not None and previous != module:
            raise ValueError("Installed SNMP module is immutable; compile a new version")
        document["modules"][name] = module
        if len(document["modules"]) > 1024:
            raise ValueError("SNMP catalog is full")
        encoded = yaml.safe_dump(document, sort_keys=True).encode()
        if len(encoded) > MAX_CATALOG:
            raise ValueError("SNMP catalog would exceed its byte limit")
        # Preserve Go's numeric enum-map keys. Never round-trip through JSON.
        verify(document["modules"], exporter=exporter)
        outcome = {"module_name": name, "expected_metrics": candidate["expected_metrics"],
            "previous_catalog_sha256": current_hash, "catalog_sha256": current_hash,
            "installed": previous is not None, "changed": False,
            "live_target_tested": False, "continuous_collection_enabled": False}
        if not confirm or previous is not None:
            return outcome
        raw_fd, raw_path = tempfile.mkstemp(prefix=".modules-", dir=catalog.parent)
        temporary = Path(raw_path)
        try:
            with os.fdopen(raw_fd, "wb") as output:
                os.fchmod(output.fileno(), stat.S_IMODE(old_info.st_mode))
                if os.geteuid() == 0: os.fchown(output.fileno(), old_info.st_uid, old_info.st_gid)
                output.write(encoded); output.flush(); os.fsync(output.fileno())
            # Serialize compliant installers; also detect noncompliant writers.
            if _read_catalog(catalog)[1] != original:
                raise ValueError("SNMP catalog changed during native validation")
            os.replace(temporary, catalog)
            directory_fd = os.open(catalog.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return {**outcome, "installed": True, "changed": True,
            "catalog_sha256": hashlib.sha256(encoded).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-catalog-sha256", required=True)
    parser.add_argument("--confirm", action="store_true", help="Append the reviewed module; does not enable collection")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("Native SNMP module installation requires protected deployment access")
        trusted_file(Path(__file__))
        trusted_file(CATALOG)
        trusted_file(EXPORTER, executable=True)
        encoded = sys.stdin.buffer.read(4_000_001)
        if len(encoded) > 4_000_000:
            raise ValueError("SNMP installation candidate is oversized")
        candidate = json.loads(encoded)
        result = install_module(candidate, catalog=CATALOG, exporter=EXPORTER,
            expected_catalog_sha256=args.expected_catalog_sha256, confirm=args.confirm)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        # Do not echo stdin, filesystem errors, YAML, raw MIBs or credentials.
        print(json.dumps({"installed": False, "error": "SNMP module installation failed; inspect candidate, catalog revision and runtime custody"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
