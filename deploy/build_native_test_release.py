"""Assemble a self-contained operator/tool layer around a verified v1 bundle.

Application artifacts are copied byte-for-byte; this builder neither downloads
packages nor uses a SHA-256 inventory. It refuses an existing output path.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

if __package__:
    from .verify_native_backend_bundle import OPERATOR_TOOLS, OPERATOR_CONFIGURATION, verify_bundle
    from .wheel_source_gate import assert_wheel_matches_source
else:
    from verify_native_backend_bundle import OPERATOR_TOOLS, OPERATOR_CONFIGURATION, verify_bundle
    from wheel_source_gate import assert_wheel_matches_source


def _equal_files(left: Path, right: Path) -> int:
    if left.stat().st_size != right.stat().st_size:
        raise ValueError(f"Copied artifact size changed: {left.name}")
    size = 0
    with left.open("rb") as a, right.open("rb") as b:
        while chunk := a.read(128 * 1024):
            if chunk != b.read(len(chunk)):
                raise ValueError(f"Copied artifact bytes changed: {left.name}")
            size += len(chunk)
        if b.read(1):
            raise ValueError(f"Copied artifact has extra bytes: {left.name}")
    return size


def _source_files(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Release source must be a real directory")
    files = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Release source contains a symlink")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise ValueError("Release source contains a non-regular entry")
    return sorted(files)


def _operator_paths(repository:Path,*,include_backend_host_preflight=False):
    paths=sorted(OPERATOR_TOOLS | OPERATOR_CONFIGURATION | {
        f"deploy/systemd/{path.name}" for path in (repository/"deploy/systemd").iterdir()
        if path.is_file() and not path.is_symlink()
    } | ({"deploy/check_native_backend_host.py"} if include_backend_host_preflight else set()))
    if any(not (repository/path).is_file() or (repository/path).is_symlink() for path in paths):
        raise ValueError("Required operator tool is missing or linked")
    return paths


def build_release(source_arg: Path, destination_arg: Path, repository_arg: Path,
                  *, include_backend_host_preflight: bool = False) -> dict:
    if not all(path.is_absolute() for path in (source_arg, destination_arg, repository_arg)):
        raise ValueError("Release builder requires absolute source, destination and repository paths")
    source, destination, repository = source_arg.resolve(), destination_arg, repository_arg.resolve()
    if destination.exists() or destination.is_symlink():
        raise ValueError("Release destination already exists; refusing to overwrite")
    if (source == destination or source in destination.parents or destination in source.parents or
            repository == destination or destination in repository.parents):
        raise ValueError("Release output must be separate from its source and repository")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("Release destination parent must be a real directory")
    if repository.is_symlink() or not repository.is_dir():
        raise ValueError("Release repository must be a real directory")
    original = json.loads((source / "release.json").read_text(encoding="utf-8"))
    if original.get("format_version") != "icheck.native-test-release-bundle/v1":
        raise ValueError("Release builder requires a verified v1 application bundle")
    verify_bundle(source, repository / "deploy/systemd")
    source_wheel_files = assert_wheel_matches_source(
        source / original["backend_wheel"], repository,
    )
    source_files = _source_files(source)
    operator_paths = _operator_paths(repository,include_backend_host_preflight=include_backend_host_preflight)

    destination.mkdir(mode=0o700)
    try:
        for child in source.iterdir():
            if child.name == "release.json":
                continue
            target = destination / child.name
            if child.is_dir():
                shutil.copytree(child, target, symlinks=True)
            elif child.is_file() and not child.is_symlink():
                shutil.copy2(child, target)
            else:
                raise ValueError("Release source contains a non-regular top-level entry")
        bytes_compared = 0
        for old in source_files:
            if old.name == "release.json" and old.parent == source:
                continue
            bytes_compared += _equal_files(old, destination / old.relative_to(source))
        for name in operator_paths:
            target = destination / "operator" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repository / name, target)
            bytes_compared += _equal_files(repository / name, target)
        source_wheel_files = assert_wheel_matches_source(
            destination / original["backend_wheel"], repository,
        )
        manifest = {**original, "format_version": "icheck.native-test-release-bundle/v2",
                    "name": destination.name, "operator_root": "operator",
                    "operator_files": operator_paths, "operator_file_count": len(operator_paths),
                    "scope": "Offline Linux test candidate with bundled operator scripts; host deployment and live acceptance remain open"}
        (destination / "release.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                                  encoding="utf-8")
        checked = verify_bundle(destination, destination / "operator/deploy/systemd")
        destination.chmod(0o755)
        return {"format_version": "icheck.native-test-release-build/v2",
                "destination": str(destination), "application_files_byte_compared": len(source_files) - 1,
                "source_wheel_files_byte_compared": source_wheel_files,
                "operator_files_byte_compared": len(operator_paths),
                "bytes_compared": bytes_compared,
                "bundle_check": checked["format_version"], "release_ready": False}
    except BaseException:
        shutil.rmtree(destination)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--include-backend-host-preflight", action="store_true")
    args = parser.parse_args()
    result = build_release(args.source, args.out, args.repository,
                           include_backend_host_preflight=args.include_backend_host_preflight)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
