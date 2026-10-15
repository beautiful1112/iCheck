"""Install a verified native backend bundle into a new, inactive virtualenv.

This tool never changes /opt/icheck/.venv, systemd state or a database. A
virtualenv is built at its final path because generated console-script shebangs
are not relocatable. A failed, newly claimed directory is removed; an existing
directory is never overwritten or removed.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True

if __package__:
    from .verify_native_backend_bundle import _constraints, _product_scripts, verify_bundle
else:
    from verify_native_backend_bundle import _constraints, _product_scripts, verify_bundle


RELEASE_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
MARKER = ".icheck-backend-stage.json"

# OS identities are trusted component boundaries, not tenant sandboxes.
# Capacity instances reuse only their corresponding database-free worker UID.
SERVICE_ACCOUNTS = {
    "icheck": (),
    "icheck-frontend": (),
    "icheck-prometheus": (),
    "icheck-monitoring-gateway": (),
    "icheck-snmp-exporter": (),
    "icheck-agent": (),
    "icheck-collector": (),
    "icheck-projection": (),
    "icheck-indicator": (),
    "icheck-workflow-dispatch": (),
    "icheck-rollout": (),
    "icheck-scaling": (),
    "icheck-quality": (),
    "icheck-ecosystem-transport": (),
    "icheck-mcp-attestor": (),
    "icheck-lease-reconciler": (),
    "icheck-capacity": (),
    "icheck-actions": (),
    # Attestation needs the actual installed exporter configuration, not API secrets.
    "icheck-attestor": ("icheck-snmp-exporter",),
}


def _account_state(name: str) -> dict:
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        try:
            grp.getgrnam(name)
        except KeyError:
            return {"account": name, "exists": False}
        raise ValueError("A service group exists without its matching account; inspect manually")
    try:
        primary = grp.getgrnam(name)
        extra = [grp.getgrnam(group).gr_gid for group in SERVICE_ACCOUNTS[name]]
    except KeyError as exc:
        raise ValueError("Service account has a missing primary or approved supplementary group") from exc
    memberships = set(os.getgrouplist(name, user.pw_gid))
    if (user.pw_uid == 0 or primary.gr_gid == 0 or user.pw_gid != primary.gr_gid
            or user.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
            or memberships != {primary.gr_gid, *extra}
            or any(other.pw_name != name and other.pw_uid == user.pw_uid for other in pwd.getpwall())
            or any(other.gr_name != name and other.gr_gid == primary.gr_gid for other in grp.getgrall())):
        raise ValueError("Service identity is root, aliased, login-enabled or has unapproved groups")
    # A different login must not inherit service credentials through this group.
    allowed_members = {name, *(account for account, groups in SERVICE_ACCOUNTS.items() if name in groups)}
    if (not set(primary.gr_mem) <= allowed_members
            or any(other.pw_gid == primary.gr_gid and other.pw_name not in allowed_members
                   for other in pwd.getpwall())):
        raise ValueError("Service primary group grants credentials to an unapproved account")
    return {"account": name, "exists": True, "uid": user.pw_uid, "gid": primary.gr_gid,
            "supplementary_groups": list(SERVICE_ACCOUNTS[name])}


def service_accounts(*, prepare: bool = False) -> dict:
    # Validate every existing account before creating anything. Never silently
    # repair/adopt an unsafe existing UID, login, group, password or home.
    initial = [_account_state(name) for name in SERVICE_ACCOUNTS]
    created = []
    if prepare:
        if os.geteuid() != 0:
            raise ValueError("Creating service identities requires the root deployment operator")
        for entry in initial:
            if entry["exists"]:
                continue
            name = entry["account"]
            command = ["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
                       "--home-dir", f"/var/lib/{name}", "--shell", "/usr/sbin/nologin"]
            if SERVICE_ACCOUNTS[name]:
                command += ["--groups", ",".join(SERVICE_ACCOUNTS[name])]
            _run([*command, name], cwd=Path("/"), timeout=30)
            _account_state(name)
            created.append(name)
    accounts = [_account_state(name) for name in SERVICE_ACCOUNTS]
    return {"format_version": "icheck.native-service-accounts/v1", "accounts": accounts,
            "created": created, "complete": all(item["exists"] for item in accounts),
            "database_changed": False, "services_changed": False,
            "active_pointer_changed": False, "existing_identities_modified": False}


def _trusted_ancestry(path: Path) -> None:
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Root staging requires root-owned, non-writable path ancestry")


def _trusted_host_source(path: Path) -> None:
    # Root must never execute a wheel from a tree another account can change
    # between validation and installation. This is not a release signature.
    _trusted_ancestry(path)
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in [*dirs, *files]:
            info = (Path(root) / name).lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                raise ValueError("Root staging requires a root-owned, non-writable, link-free bundle")


def _run(command: list[str], *, cwd: Path, timeout: int = 300) -> str:
    # Do not inherit application/database credentials or pip/index settings.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("ICHECK_", "PIP_", "PYTHON", "VIRTUAL_ENV"))
           and key not in {"DATABASE_URL", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"}}
    env.update({"PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    # Entry-point imports can load dotenv relative to cwd. Run inside our
    # exclusively claimed environment, not the caller's checkout or home.
    completed = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                               timeout=timeout, check=False)
    if completed.returncode:
        # Installer/driver error bodies can contain environment or URL secrets.
        raise RuntimeError(f"Staged backend command failed ({Path(command[0]).name}, exit {completed.returncode})")
    return completed.stdout.strip()


def _harden(path: Path, owner_uid: int, owner_gid: int) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        if info.st_uid != owner_uid or info.st_gid != owner_gid:
            os.lchown(path, owner_uid, owner_gid)
        return
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise ValueError("Staged backend contains a non-regular entry")
    if stat.S_ISDIR(info.st_mode):
        for child in path.iterdir():
            _harden(child, owner_uid, owner_gid)
    if info.st_uid != owner_uid or info.st_gid != owner_gid:
        os.chown(path, owner_uid, owner_gid)
    path.chmod(0o555 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o444)


def _cleanup_claim(path: Path) -> None:
    for root, dirs, _ in os.walk(path, topdown=True, followlinks=False):
        Path(root).chmod(0o700)
        for name in dirs:
            child = Path(root) / name
            if not child.is_symlink():
                child.chmod(0o700)
    shutil.rmtree(path)


def _strip_bytecode(path: Path) -> None:
    # Pip compiles .pyc even when child imports are configured not to write
    # bytecode. A sealed source tree must not retain an alternate executable
    # copy that the wheel-byte comparison cannot authenticate.
    for root, directories, files in os.walk(path, topdown=True, followlinks=False):
        for name in list(directories):
            if name == "__pycache__":
                cache = Path(root) / name
                if cache.is_symlink():
                    raise ValueError("Staged backend contains a linked bytecode cache")
                shutil.rmtree(cache)
                directories.remove(name)
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                (Path(root) / name).unlink()


def stage_backend(bundle_arg: Path, units_arg: Path, release_root_arg: Path,
                  *, owner_uid: int, owner_gid: int) -> dict:
    for path in (bundle_arg, units_arg, release_root_arg):
        if not path.is_absolute():
            raise ValueError("Bundle, unit and release-root paths must be absolute")
    bundle, units, release_root = bundle_arg.resolve(), units_arg.resolve(), release_root_arg
    if release_root.resolve() != release_root or release_root.is_symlink():
        raise ValueError("Backend release root must not be a symlink")
    root_info = release_root.stat()
    if root_info.st_uid != owner_uid or root_info.st_gid != owner_gid or root_info.st_mode & 0o022:
        raise ValueError("Backend release root must be package-owned and not group/other writable")
    if bundle == release_root or release_root in bundle.parents or bundle in release_root.parents:
        raise ValueError("Bundle and backend release root must be separate trees")
    if owner_uid == 0:
        _trusted_host_source(bundle_arg)
        _trusted_host_source(units_arg)
        _trusted_ancestry(release_root)
    release_id = bundle.name
    if not RELEASE_ID.fullmatch(release_id) or release_id == "none":
        raise ValueError("Bundle name is not a safe backend release ID")
    destination = release_root / release_id
    if destination.exists() or destination.is_symlink():
        raise ValueError("Backend release destination already exists; refusing to overwrite")
    checked = verify_bundle(bundle, units)
    constraints = _constraints(bundle / "backend-runtime/backend-constraints.txt")
    runtime = json.loads((bundle / "backend-runtime/backend-runtime.json").read_text(encoding="utf-8"))
    scripts = _product_scripts(bundle / checked["product_wheel"])
    if sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 12, 3):
        raise ValueError("This selected backend bundle requires CPython 3.12.3")

    # The exclusive 0700 claim keeps an incomplete environment inaccessible
    # to the dedicated service user. The existing active pointer is untouched.
    destination.mkdir(mode=0o700)
    try:
        _run([sys.executable, "-m", "venv", "--symlinks", str(destination)], cwd=destination)
        interpreter = destination / "bin/python"
        wheel = bundle / checked["product_wheel"]
        _run([str(interpreter), "-m", "pip", "--isolated", "install", "--no-index",
              "--only-binary=:all:", "--no-cache-dir", "--find-links",
              str(bundle / "backend-wheelhouse"), "--constraint",
              str(bundle / "backend-runtime/backend-constraints.txt"),
              f"{wheel}[{','.join(runtime['extras'])}]"], cwd=destination, timeout=600)
        _run([str(interpreter), "-m", "pip", "check"], cwd=destination)
        installed = json.loads(_run([str(interpreter), "-c",
            "import importlib.metadata as m,json,sys; "
            "print(json.dumps({n:m.version(n) for n in json.loads(sys.argv[1])}))",
            json.dumps([*constraints, "icheck"])], cwd=destination))
        for name, version in constraints.items():
            if installed.get(name) != str(version):
                raise ValueError(f"Staged backend dependency version differs: {name}")
        if installed.get("icheck") != runtime["version"]:
            raise ValueError("Staged backend product version differs")
        if any(not (destination / "bin" / script).is_file() for script in scripts | {"uvicorn"}):
            raise ValueError("Staged backend is missing required console scripts")
        loaded_scripts = int(_run([str(interpreter), "-c",
            "import importlib.metadata as m; "
            "entries=[e for e in m.distribution('icheck').entry_points if e.group=='console_scripts']; "
            "loaded=[e.load() for e in entries]; "
            "raise_error=next((e.name for e,f in zip(entries,loaded) if not callable(f)),None); "
            "print(len(entries) if raise_error is None else 0)"], cwd=destination))
        if loaded_scripts != len(scripts):
            raise ValueError("Staged backend console entry points are not all callable")
        head = _run([str(destination / "bin/icheck-db"), "heads"], cwd=destination)
        if not head or "(head)" not in head:
            raise ValueError("Installed backend migration head is unavailable")
        _strip_bytecode(destination)
        result = {"format_version": "icheck.native-backend-stage/v1", "release_id": release_id,
                  "destination": str(destination), "product_wheel": wheel.name,
                  "pinned_dependencies": len(constraints), "product_console_scripts": len(scripts),
                  "console_scripts": sorted(scripts),
                  "migration_head": head, "active_pointer_changed": False,
                  "database_changed": False, "services_changed": False}
        # Harden contents first, then write the completion marker, and seal
        # the root last. A partial crash leaves a non-0555 root or no marker.
        for child in destination.iterdir():
            _harden(child, owner_uid, owner_gid)
        marker = destination / MARKER
        marker.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        _harden(marker, owner_uid, owner_gid)
        destination.chmod(0o555)
        return result
    except BaseException:
        _cleanup_claim(destination)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, nargs="?", help="Absolute path to the verified release bundle")
    parser.add_argument("--units", type=Path, default=Path(__file__).parent / "systemd")
    parser.add_argument("--release-root", type=Path, default=Path("/opt/icheck/backend-releases"))
    parser.add_argument("--service-accounts", choices=("inspect", "prepare"),
                        help="Inspect or explicitly prepare fixed isolated OS identities; do not stage a release")
    parser.add_argument("--acknowledge-accounts", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Native backend host staging requires the root deployment operator")
    try:
        _trusted_host_source(Path(__file__).resolve().parent)
        if args.service_accounts:
            if args.bundle is not None or (args.service_accounts == "prepare" and not args.acknowledge_accounts):
                parser.error("Account mode excludes a bundle; preparing identities requires --acknowledge-accounts")
            result = service_accounts(prepare=args.service_accounts == "prepare")
        else:
            if args.bundle is None or args.acknowledge_accounts:
                parser.error("Staging requires a bundle; --acknowledge-accounts is only for account preparation")
            result = stage_backend(args.bundle, args.units, args.release_root,
                                   owner_uid=0, owner_gid=0)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Native backend staging failed ({type(error).__name__}). "
                       "Inspect prerequisites and the inactive release root before retrying.\n")
    print(json.dumps(result, sort_keys=True))
    if args.service_accounts and not result["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
