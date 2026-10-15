"""Provision native managed AI encryption custody once; never accept or print API keys.

Run a reviewed, root-owned copy of this helper. It preserves an existing master
key and all other API configuration. It does not restart services or contact AI.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import stat
import sys

if __package__:
    from .preview_native_access import ENV, trusted, parse_environment, atomic_environment
else:
    # Isolated Python omits the script directory. Add only sealed, root-owned
    # sibling tooling, after checking its complete path ancestry.
    tooling = Path(__file__).absolute().parent
    for item in (Path(__file__).absolute(), tooling / "preview_native_access.py", tooling, *tooling.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe managed AI installer tooling")
    sys.path.insert(0, str(tooling))
    from preview_native_access import ENV, trusted, parse_environment, atomic_environment

KEY_PATH = Path("/etc/icheck/ai-managed-secret.key")
SETTING = "ICHECK_AI_MANAGED_SECRET_KEY_FILE"


def provision_key(path: Path, gid: int) -> bool:
    """Parent custody is checked by the administrative entry point."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o400)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != gid
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o440 or len(handle.read(33)) != 32):
                raise ValueError("Existing managed AI key custody is unsafe; refusing to replace it")
        return False
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), os.geteuid(), gid)
            handle.write(os.urandom(32))
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o440)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return True
    except BaseException:
        # Retain any created file for explicit operator inspection; never silently regenerate custody.
        raise


def prepare() -> dict:
    if os.geteuid() != 0:
        raise ValueError("Native key provisioning requires the server administrator")
    trusted(Path(__file__).resolve())
    trusted(KEY_PATH.parent)
    trusted(ENV)
    values = parse_environment(ENV.read_text())
    for key, value in {"ICHECK_ENVIRONMENT": "production", "ICHECK_CONTROL_PLANE_AUTH_MODE": "required",
                       "ICHECK_CONTROL_PLANE_SESSION_COOKIE_SECURE": "true", "ICHECK_AUTO_CREATE_SCHEMA": "false"}.items():
        if values.get(key) != value:
            raise ValueError("Native managed AI security prerequisites are not configured")
    if values.get(SETTING) not in {None, "", str(KEY_PATH)}:
        raise ValueError("An encryption key path is already configured; inspect before changing custody")
    created = provision_key(KEY_PATH, grp.getgrnam("icheck").gr_gid)
    values[SETTING] = str(KEY_PATH)
    atomic_environment(values)
    return {"key_created": created, "key_path": str(KEY_PATH), "key_mode": "0440", "configuration_updated": True,
            "service_restart_required": True, "ai_network_access_changed": False, "api_key_provisioned": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-key-provisioning", action="store_true", required=True)
    parser.parse_args()
    try:
        print(json.dumps(prepare(), sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError):
        print("Managed AI provisioning failed. Check trusted paths, permissions and existing custody; secrets were not printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
