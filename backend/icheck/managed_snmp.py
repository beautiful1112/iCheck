"""Short-lived native SNMP Exporter with an attempt-local protected auth config.

No community is put in argv, URLs, the shared exporter configuration or logs.
Only root-provisioned modules and binary paths may be used. Temp custody is
private to the Collector/gateway user and removed on success and failure.
"""
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import yaml


def trusted_file(path, *, executable=False):
    p = Path(path)
    if not p.is_absolute():
        raise ValueError("Managed SNMP path must be absolute")
    for item in (p, *p.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("Managed SNMP runtime custody is unsafe")
    if not p.is_file() or (executable and not os.access(p, os.X_OK)):
        raise ValueError("Managed SNMP runtime is unavailable")
    return p


@lru_cache(maxsize=4)
def _load_module_document(path, identity):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        actual = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if actual != identity or not stat.S_ISREG(info.st_mode):
            raise ValueError("SNMP module catalog changed while being read")
        document = yaml.load(handle.read(20_000_001), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    if not isinstance(document, dict) or set(document) != {"modules"} or not isinstance(document["modules"], dict):
        raise ValueError("SNMP runtime configuration must contain modules only")
    return document


def module_document():
    source = trusted_file(os.environ.get("ICHECK_MANAGED_SNMP_MODULES_FILE", "/etc/icheck-workers/snmp-runtime/modules.yml"))
    info = source.stat()
    if info.st_size > 20_000_000:
        raise ValueError("SNMP module configuration exceeds its size bound")
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    # Cache modules ONLY; return a copy so attempt-local auth cannot enter cache.
    return deepcopy(_load_module_document(str(source), identity))


@contextmanager
def exporter(credential, *, timeout_seconds=15, identity_only=False, requested_modules=None):
    community = credential.get("community")
    if not isinstance(community, str) or not 1 <= len(community) <= 255:
        raise ValueError("Managed SNMP requires an SNMPv2c community credential")
    binary = trusted_file(os.environ.get("ICHECK_MANAGED_SNMP_EXPORTER_BINARY", "/opt/icheck/bin/snmp_exporter"), executable=True)
    document = module_document()
    if requested_modules is not None:
        from .snmp_modules import validate_modules
        names = validate_modules(requested_modules, available=document["modules"])
        document["modules"] = {name: document["modules"][name] for name in names}
    if identity_only:
        # A fixed four-scalar GET, not a walk over every interface or sysOR row.
        # This module is private to this attempt and cannot be supplied by chat.
        from .snmp_modules import IDENTITY_MODULE
        scalars = [("sysDescr", "1", "DisplayString"), ("sysObjectID", "2", "DisplayString"),
            ("sysUpTime", "3", "gauge"), ("sysName", "5", "DisplayString")]
        document["modules"] = {IDENTITY_MODULE: {
            "get": [f"1.3.6.1.2.1.1.{oid}.0" for _, oid, _ in scalars],
            "metrics": [{"name": name, "oid": f"1.3.6.1.2.1.1.{oid}", "type": kind,
                "help": "Bounded SNMP identity scalar"} for name, oid, kind in scalars],
            "timeout": f"{max(1, min(timeout_seconds - 1, 5))}s", "retries": 0}}
    document["auths"] = {"managed": {"version": 2, "community": community}}
    process = None
    with tempfile.TemporaryDirectory(prefix="icheck-snmp-") as directory:
        path = Path(directory) / "snmp.yml"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            # Preserve numeric enum-map keys: JSON would stringify them and Go's
            # strict YAML parser rejects those in real if_mib modules. Safe YAML
            # serialization also quotes community strings without config injection.
            yaml.safe_dump(document, handle, sort_keys=False)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
        try:
            process = subprocess.Popen([str(binary), "--config.file=" + str(path),
                "--web.listen-address=127.0.0.1:" + str(port)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                env={"PATH": "/usr/bin:/bin", "GOMAXPROCS": "1"})
            deadline = time.monotonic() + min(5, timeout_seconds)
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("Managed SNMP Exporter failed to start")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.03)
            yield "http://127.0.0.1:" + str(port)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2)
