"""Read-only installed-backend and systemd preflight for the first native release.

This does not read environment-file contents, connect to a database, change
units or start a service. A passing result is still not a live traffic test.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
from zipfile import BadZipFile, ZipFile

sys.dont_write_bytecode = True

if __package__:
    from .stage_native_backend import _account_state, _trusted_ancestry, SERVICE_ACCOUNTS
    from .switch_native_backend import read_active_backend
    from .verify_native_backend_bundle import REQUIRED_PYTHON_UNITS, verify_bundle
else:
    from stage_native_backend import _account_state, _trusted_ancestry, SERVICE_ACCOUNTS
    from switch_native_backend import read_active_backend
    from verify_native_backend_bundle import REQUIRED_PYTHON_UNITS, verify_bundle


OPTIONAL_UNITS = {
    "icheck-agent-capacity@.service", "icheck-collector-capacity@.service",
    "icheck-snmp-attestor@.service", "icheck-ansible-adapter.service",
}
REQUIRED_UNITS = REQUIRED_PYTHON_UNITS - OPTIONAL_UNITS


def _field(source: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}=(.*)$", source, re.MULTILINE)
    return match.group(1).strip() if match else None


def _same_bytes(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as a, right.open("rb") as b:
        while chunk := a.read(64 * 1024):
            if chunk != b.read(len(chunk)):
                return False
        return not b.read(1)


def installed_payload_matches_wheel(wheel_path: Path, release: Path) -> tuple[bool, int]:
    """Compare staged application/migration bytes and names with the candidate wheel."""

    site_packages = release / "lib/python3.12/site-packages"
    try:
        with ZipFile(wheel_path) as wheel:
            members = [item for item in wheel.infolist()
                       if not item.is_dir() and item.filename.startswith(("icheck/", "migrations/"))]
            expected = {item.filename for item in members}
            if not members or len(expected) != len(members):
                return False, 0
            actual: set[str] = set()
            for root_name in ("icheck", "migrations"):
                root = site_packages / root_name
                if not root.is_dir() or root.is_symlink():
                    return False, 0
                for path in root.rglob("*"):
                    relative = path.relative_to(site_packages)
                    if "__pycache__" in relative.parts:
                        continue
                    if path.is_symlink():
                        return False, len(actual)
                    if path.is_file():
                        actual.add(relative.as_posix())
                    elif not path.is_dir():
                        return False, len(actual)
            if actual != expected:
                return False, len(actual)
            for item in members:
                target = site_packages / item.filename
                if target.is_symlink() or target.stat().st_size != item.file_size:
                    return False, len(actual)
                with wheel.open(item) as source, target.open("rb") as installed:
                    while chunk := source.read(64 * 1024):
                        if chunk != installed.read(len(chunk)):
                            return False, len(actual)
                    if installed.read(1):
                        return False, len(actual)
            return True, len(actual)
    except (BadZipFile, OSError, ValueError):
        return False, 0


def systemd_unit_state(name: str) -> dict[str, str]:
    completed = subprocess.run(["/usr/bin/systemctl", "show", name,
        "--property=Id,LoadState,ActiveState,MainPID,FragmentPath,DropInPaths,User,Group,ExecStart",
        "--no-pager"], capture_output=True, text=True, timeout=5, check=False)
    if completed.returncode:
        raise RuntimeError("Could not read installed systemd unit")
    return dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)


def service_identity() -> tuple[int, int] | None:
    try:
        user, group = pwd.getpwnam("icheck"), grp.getgrnam("icheck")
    except KeyError:
        return None
    if user.pw_uid == 0 or group.gr_gid == 0 or user.pw_gid != group.gr_gid:
        return None
    return user.pw_uid, user.pw_gid


def service_account_isolated(name: str | None, group: str | None) -> bool:
    if name not in SERVICE_ACCOUNTS or group != name:
        return False
    try:
        return _account_state(name)["exists"] is True
    except (OSError, ValueError):
        return False


def service_can_read_head(active_link: Path, expected_head: str) -> bool:
    if os.geteuid() != 0:
        return False
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONNOUSERSITE": "1",
           "PYTHONDONTWRITEBYTECODE": "1"}
    completed = subprocess.run(["/usr/sbin/runuser", "-u", "icheck", "--",
                                str(active_link / "bin/icheck-db"), "heads"],
                               cwd="/", env=env, capture_output=True, text=True,
                               timeout=20, check=False)
    return completed.returncode == 0 and completed.stdout.strip() == expected_head


def inspect_backend_host(candidate: Path, release_root: Path, active_link: Path,
                         *, owner_uid: int, owner_gid: int,
                         read_unit=systemd_unit_state, identity=service_identity,
                         check_service=service_can_read_head,
                         check_payload=installed_payload_matches_wheel,
                         check_account=service_account_isolated) -> dict:
    if not all(path.is_absolute() for path in (candidate, release_root, active_link)):
        raise ValueError("Host preflight requires absolute candidate and release paths")
    failures: list[str] = []
    candidate_units = candidate / "operator/deploy/systemd"
    bundle_valid = False
    candidate_wheel = None
    try:
        checked = verify_bundle(candidate, candidate_units)
        bundle_valid = checked["format_version"] == "icheck.native-backend-bundle-check/v2"
        candidate_wheel = checked["product_wheel"]
        if not bundle_valid:
            failures.append("candidate is not a checkout-independent v2 native bundle")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        failures.append("candidate release bundle failed structural/runtime verification")
    account = identity()
    if account is None:
        failures.append("dedicated icheck account/group is missing or mismatched")

    active_id = None
    active_valid = False
    installed_payload_equal = False
    installed_payload_files = 0
    head = None
    try:
        active_id = read_active_backend(release_root, active_link, uid=owner_uid, gid=owner_gid)
        if active_id != candidate.name:
            failures.append("active backend pointer does not select the candidate release")
        else:
            marker = json.loads((release_root / active_id / ".icheck-backend-stage.json")
                                .read_text(encoding="utf-8"))
            head = marker.get("migration_head")
            active_valid = bundle_valid and marker.get("product_wheel") == candidate_wheel
            if not active_valid:
                failures.append("active backend marker differs from the candidate product")
            else:
                installed_payload_equal, installed_payload_files = check_payload(
                    candidate / candidate_wheel, release_root / active_id,
                )
                if not installed_payload_equal:
                    failures.append("installed backend application bytes differ from the candidate wheel")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        failures.append("active backend pointer or staged release permissions are invalid")

    unit_results = {}
    for name in sorted(REQUIRED_UNITS):
        item = {"loaded": False, "active": False, "fragment_byte_equal": False,
                "account_matches": False, "account_isolated": False,
                "command_matches": False, "drop_ins_absent": False}
        try:
            state = read_unit(name)
            source = (candidate_units / name).read_text(encoding="utf-8")
            fragment_name = state.get("FragmentPath", "")
            fragment = Path(fragment_name) if fragment_name.startswith("/") else None
            item["loaded"] = state.get("Id") == name and state.get("LoadState") == "loaded"
            item["active"] = (state.get("ActiveState") == "active" and
                              state.get("MainPID", "0").isdigit() and int(state["MainPID"]) > 0)
            item["drop_ins_absent"] = not state.get("DropInPaths")
            item["account_matches"] = (state.get("User") == _field(source, "User") and
                                       state.get("Group") == _field(source, "Group"))
            item["account_isolated"] = check_account(state.get("User"), state.get("Group")) is True
            expected_command = _field(source, "ExecStart")
            paths = re.findall(r"\bpath=([^ ;]+)\s*;", state.get("ExecStart", ""))
            item["command_matches"] = bool(expected_command and len(paths) == 1 and
                                           paths[0] == expected_command.split()[0])
            if fragment and fragment.is_file() and not fragment.is_symlink():
                info = fragment.stat()
                if (info.st_uid == owner_uid and not info.st_mode & 0o022 and
                        (owner_uid != 0 or _trusted_ancestry(fragment.parent) is None)):
                    item["fragment_byte_equal"] = _same_bytes(candidate_units / name, fragment)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            pass
        unit_results[name] = item
        if not all(item.values()):
            failures.append(f"{name} is not loaded/running with the approved unit fragment")

    action_disabled = False
    try:
        action = read_unit("icheck-ansible-adapter.service")
        action_disabled = action.get("ActiveState") in {"inactive", "failed"}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        pass
    if not action_disabled:
        failures.append("unqualified optional Ansible action adapter is active or uninspectable")

    service_head_access = False
    if active_valid and account is not None and isinstance(head, str):
        try:
            service_head_access = check_service(active_link, head) is True
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass
    if not service_head_access:
        failures.append("icheck service-account migration-head execution is unverified")
    return {"format_version": "icheck.native-backend-host-preflight/v1",
            "candidate_release": candidate.name, "candidate_verified": bundle_valid,
            "active_release": active_id, "active_release_valid": active_valid,
            "installed_payload_byte_equal": installed_payload_equal,
            "installed_payload_files_checked": installed_payload_files,
            "service_account_exists": account is not None,
            "service_account_heads_executed": service_head_access,
            "required_units": len(REQUIRED_UNITS), "unit_checks": unit_results,
            "unqualified_action_adapter_disabled": action_disabled,
            "database_and_remote_drain_checked": False,
            "failures": failures, "passed": not failures}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="Absolute path to the selected v2 native bundle")
    args = parser.parse_args()
    try:
        result = inspect_backend_host(args.candidate, Path("/opt/icheck/backend-releases"),
                                      Path("/opt/icheck/.venv"), owner_uid=0, owner_gid=0)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Native backend host preflight failed ({type(error).__name__}).\n")
    print(json.dumps(result, sort_keys=True))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
