"""Switch a stopped native backend fleet to a retained, schema-matched release.

The command does not stop services, contact a database, migrate schemas or
assert remote-host drain. Those prerequisites must be established separately.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from uuid import uuid4

sys.dont_write_bytecode = True

if __package__:
    from .stage_native_backend import MARKER, RELEASE_ID, _trusted_host_source, _trusted_ancestry
    from .verify_native_backend_bundle import EXTERNAL_UNITS, REQUIRED_PYTHON_UNITS, OPTIONAL_NATIVE_UNITS
else:
    from stage_native_backend import MARKER, RELEASE_ID, _trusted_host_source, _trusted_ancestry
    from verify_native_backend_bundle import EXTERNAL_UNITS, REQUIRED_PYTHON_UNITS, OPTIONAL_NATIVE_UNITS


REVISION = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
INSTANCE = re.compile(r"icheck-(?:agent-capacity|collector-capacity|snmp-attestor)@[^/\s]+\.service\Z")
PLAIN_UNITS = REQUIRED_PYTHON_UNITS - {
    "icheck-agent-capacity@.service", "icheck-collector-capacity@.service",
    "icheck-snmp-attestor@.service",
}
PLAIN_UNITS |= {name for name, command in OPTIONAL_NATIVE_UNITS.items()
                if command.startswith('/opt/icheck/.venv/bin/')}
NATIVE_EXTERNAL_UNITS = {**EXTERNAL_UNITS, **{name:command.split()[0]
    for name,command in OPTIONAL_NATIVE_UNITS.items() if not command.startswith('/opt/icheck/.venv/bin/')}}


def _entry(path: Path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _safe_parent(path: Path, uid: int) -> None:
    if path.resolve() != path or not path.is_dir():
        raise ValueError("Backend release parent must be a real directory")
    info = path.stat()
    if info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError("Backend release parent must be package-owned and not group/other writable")


def _audit_release_tree(path: Path, uid: int, gid: int) -> None:
    base_python = Path(sys._base_executable).resolve()
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in [*dirs, *files]:
            child = Path(root) / name
            info = child.lstat()
            if name == "__pycache__" or name.endswith((".pyc", ".pyo")):
                raise ValueError("Backend release contains executable bytecode outside the reviewed wheel")
            if info.st_uid != uid or info.st_gid != gid:
                raise ValueError("Backend release ownership changed after staging")
            if stat.S_ISLNK(info.st_mode):
                target = child.resolve(strict=True)
                if target == base_python and child.parent == path / "bin" and name in {
                    "python", "python3", "python3.12"
                }:
                    continue
                if target != path and path not in target.parents:
                    raise ValueError("Backend release contains an escaping symlink")
            elif stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o555:
                    raise ValueError("Backend release contains an unsealed directory")
            elif stat.S_ISREG(info.st_mode):
                if stat.S_IMODE(info.st_mode) not in {0o444, 0o555}:
                    raise ValueError("Backend release contains an unsealed file")
            else:
                raise ValueError("Backend release contains a non-regular entry")


def _release(path: Path, release_root: Path, uid: int, gid: int) -> dict:
    info = _entry(path)
    if not info or not stat.S_ISDIR(info.st_mode) or path.resolve() != path or (
        info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o555
    ):
        raise ValueError("Backend release is missing, linked, unowned or unsealed")
    if path.parent != release_root or not RELEASE_ID.fullmatch(path.name) or path.name == "none":
        raise ValueError("Backend release is outside the retained release root")
    marker_path = path / MARKER
    marker_info = marker_path.lstat()
    if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != uid or
            marker_info.st_gid != gid or stat.S_IMODE(marker_info.st_mode) != 0o444):
        raise ValueError("Backend completion marker is missing or unsealed")
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    scripts = marker.get("console_scripts")
    if (marker.get("format_version") != "icheck.native-backend-stage/v1" or
            marker.get("release_id") != path.name or marker.get("destination") != str(path) or
            not isinstance(scripts, list) or not scripts or
            marker.get("product_console_scripts") != len(scripts) or len(set(scripts)) != len(scripts) or
            not all(isinstance(name, str) and re.fullmatch(r"[a-z0-9_-]+", name) for name in scripts) or
            not isinstance(marker.get("pinned_dependencies"), int) or
            marker["pinned_dependencies"] <= 0 or
            any(marker.get(name) is not False for name in
                ("active_pointer_changed", "database_changed", "services_changed"))):
        raise ValueError("Backend completion marker is inconsistent")
    head = marker.get("migration_head")
    if not isinstance(head, str) or not head.endswith(" (head)") or not REVISION.fullmatch(head[:-7]):
        raise ValueError("Backend migration head is invalid")
    _audit_release_tree(path, uid, gid)
    if any(not (path / "bin" / name).is_file() for name in [*scripts, "uvicorn", "icheck-db"]):
        raise ValueError("Backend release is missing a staged command")
    return marker


def read_active_backend(release_root: Path, link: Path, *, uid: int, gid: int) -> str | None:
    info = _entry(link)
    if info is None:
        return None
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_gid != gid:
        raise ValueError("Active backend path is not a package-owned symlink")
    target = os.readlink(link)
    if os.path.isabs(target):
        raise ValueError("Active backend symlink must be relative")
    release = Path(os.path.normpath(link.parent / target))
    if (release.parent != release_root or not RELEASE_ID.fullmatch(release.name) or
            release.resolve(strict=True) != release or
            target != os.path.relpath(release, link.parent)):
        raise ValueError("Active backend symlink escapes retained releases")
    _release(release, release_root, uid, gid)
    return release.name


def switch_backend(release_root: Path, link: Path, *, to_release: str,
                   expected_release: str, database_revision: str,
                   assert_stopped, read_database_revision, uid: int, gid: int) -> dict:
    if (not release_root.is_absolute() or not link.is_absolute() or
            not RELEASE_ID.fullmatch(to_release) or to_release == "none" or
            (expected_release != "none" and not RELEASE_ID.fullmatch(expected_release)) or
            not REVISION.fullmatch(database_revision) or not callable(assert_stopped) or
            not callable(read_database_revision)):
        raise ValueError("Backend cutover requires absolute paths, exact IDs, revision and state guards")
    if release_root.parent != link.parent or release_root.name != "backend-releases" or link.name != ".venv":
        raise ValueError("Backend cutover requires fixed sibling release and active paths")
    _safe_parent(release_root, uid)
    _safe_parent(link.parent, uid)
    lock = release_root / ".switch-lock"
    if _entry(lock):
        raise ValueError("Backend switch lock exists; inspect the previous cutover")
    lock.mkdir(mode=0o700)
    temporary = None
    swapped = False
    try:
        previous = read_active_backend(release_root, link, uid=uid, gid=gid)
        if (previous or "none") != expected_release:
            raise ValueError("Active backend changed; expected-release comparison refused cutover")
        target = release_root / to_release
        marker = _release(target, release_root, uid, gid)
        if marker["migration_head"] != f"{database_revision} (head)":
            raise ValueError("Target backend migration head differs from acknowledged database revision")
        if assert_stopped() is not True:
            raise ValueError("Backend API/Worker units are not confirmed stopped")
        if read_database_revision(target) != database_revision:
            raise ValueError("Live database revision differs from the target backend head")
        if previous == to_release:
            return {"format_version": "icheck.native-backend-switch/v1",
                    "previous": previous, "current": to_release, "changed": False}
        temporary = link.parent / f".venv-next-{uuid4()}"
        os.symlink(os.path.relpath(target, link.parent), temporary)
        _fsync_directory(link.parent)
        if ((read_active_backend(release_root, link, uid=uid, gid=gid) or "none") != expected_release or
                assert_stopped() is not True or
                read_database_revision(target) != database_revision or
                _release(target, release_root, uid, gid)["migration_head"] != f"{database_revision} (head)"):
            raise ValueError("Backend cutover state changed before pointer swap")
        os.replace(temporary, link)
        swapped = True
        temporary = None
        _fsync_directory(link.parent)
        return {"format_version": "icheck.native-backend-switch/v1",
                "previous": previous or "none", "current": to_release, "changed": True,
                "database_revision_acknowledged": database_revision,
                "services_changed": False, "database_changed": False}
    except BaseException as error:
        if swapped:
            raise RuntimeError("Backend pointer may have switched; inspect active release before retrying") from error
        raise
    finally:
        if temporary is not None and _entry(temporary):
            temporary.unlink()
        lock.rmdir()


def _systemctl(*args: str) -> str:
    completed = subprocess.run(["/usr/bin/systemctl", *args], capture_output=True,
                               text=True, timeout=5, check=False)
    if completed.returncode:
        raise RuntimeError("Could not inspect systemd backend unit state")
    return completed.stdout


def stopped_backend_units() -> bool:
    entries = json.loads(_systemctl("list-units", "--all", "--type=service", "icheck-*",
                                    "--output=json", "--no-pager"))
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("unit"), str):
            return False
        name = entry["unit"]
        if name not in NATIVE_EXTERNAL_UNITS and name not in PLAIN_UNITS and not INSTANCE.fullmatch(name):
            return False
        values = {}
        for line in _systemctl("show", name, "--property=Id,LoadState,ActiveState,MainPID,ControlPID,ExecStart",
                               "--no-pager").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        commands = re.findall(r"\bpath=([^ ;]+)\s*;", values.get("ExecStart", ""))
        if values.get("Id") != name or values.get("LoadState") != "loaded" or len(commands) != 1:
            return False
        if name in NATIVE_EXTERNAL_UNITS:
            if commands[0] != NATIVE_EXTERNAL_UNITS[name]:
                return False
            continue
        if (not commands[0].startswith("/opt/icheck/.venv/bin/") or
                values.get("ActiveState") not in {"inactive", "failed"} or
                values.get("MainPID") != "0" or values.get("ControlPID") != "0"):
            return False
    return True


def current_database_revision(release: Path, *, timeout_seconds: int = 20) -> str:
    if type(timeout_seconds) is not int or timeout_seconds not in {20, 60, 120}:
        raise ValueError("Schema check timeout must be 20, 60 or 120 seconds")
    url = os.environ.get("ICHECK_DATABASE_URL", "").strip()
    if not url:
        raise ValueError("Set ICHECK_DATABASE_URL for a read-only current-revision check")
    env = {"ICHECK_DATABASE_URL": url, "PYTHONNOUSERSITE": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    completed = subprocess.run([str(release / "bin/icheck-db"), "current"],
                               cwd="/", env=env, capture_output=True, text=True,
                               timeout=timeout_seconds, check=False)
    if completed.returncode:
        # A driver failure may include the URL or credentials on stderr.
        raise RuntimeError("Read-only database revision check failed")
    lines = completed.stdout.strip().splitlines()
    if len(lines) != 1 or not lines[0].endswith(" (head)") or not REVISION.fullmatch(lines[0][:-7]):
        raise ValueError("Database does not report exactly one target migration head")
    return lines[0][:-7]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--to", required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--database-revision", required=True)
    parser.add_argument("--database-check-timeout-seconds", type=int, choices=(20, 60, 120), default=20,
        help="Bound only the read-only schema CLI on slow hosts; all schema and drain guards remain required")
    parser.add_argument("--acknowledge-drained", action="store_true")
    parser.add_argument("--acknowledge-schema-compatible", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Backend cutover requires the root deployment operator")
    if not args.acknowledge_drained or not args.acknowledge_schema_compatible:
        parser.error("Cutover requires explicit all-host drain and target-code schema compatibility acknowledgements")
    try:
        _trusted_host_source(Path(__file__).resolve().parent)
        _trusted_ancestry(Path("/opt/icheck/backend-releases"))
        result = switch_backend(Path("/opt/icheck/backend-releases"), Path("/opt/icheck/.venv"),
                                to_release=args.to, expected_release=args.expect,
                                database_revision=args.database_revision,
                                assert_stopped=stopped_backend_units,
                                read_database_revision=lambda release: current_database_revision(
                                    release, timeout_seconds=args.database_check_timeout_seconds), uid=0, gid=0)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Native backend switch failed ({type(error).__name__}). "
                       "Inspect active pointer, local units and schema evidence before retrying.\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
