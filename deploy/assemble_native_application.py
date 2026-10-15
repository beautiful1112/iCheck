"""Assemble new pinned application artifacts without changing an installed host.

This is the input layer for build_native_test_release, not a refresh of an old
runtime. Existing destinations are never overwritten. Verification compares
source/artifact bytes directly and does not create a SHA inventory.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit

if __package__:
    from .build_native_test_release import _equal_files, _source_files
    from .verify_native_backend_bundle import verify_bundle
    from .wheel_source_gate import assert_wheel_matches_source
else:
    from build_native_test_release import _equal_files, _source_files
    from verify_native_backend_bundle import verify_bundle
    from wheel_source_gate import assert_wheel_matches_source


def assemble_application(*, wheel: Path, runtime: Path, wheelhouse: Path,
                         frontend: Path, repository: Path, destination: Path,
                         include_operator:bool=False) -> dict:
    inputs = (wheel, runtime, wheelhouse, frontend, repository, destination)
    if not all(path.is_absolute() for path in inputs):
        raise ValueError("Application assembly requires absolute artifact paths")
    if any(path.is_symlink() for path in inputs):
        raise ValueError("Application assembly does not accept linked artifact roots")
    if destination.exists():
        raise ValueError("Application destination already exists; refusing to overwrite")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("Application destination parent must be a real directory")
    source_roots = [path.resolve() for path in (runtime, wheelhouse, frontend, repository)]
    resolved_destination = destination.resolve()
    if any(root == resolved_destination or root in resolved_destination.parents
           or resolved_destination in root.parents for root in source_roots):
        raise ValueError("Application destination must be separate from every input tree")
    runtime_files = _source_files(runtime)
    if {path.relative_to(runtime).as_posix() for path in runtime_files} != {
        "backend-runtime.json", "backend-constraints.txt",
    }:
        raise ValueError("Runtime input must contain exactly its manifest and constraints")
    wheelhouse_files = _source_files(wheelhouse)
    if not wheelhouse_files or any(path.parent != wheelhouse or path.suffix != ".whl"
                                  for path in wheelhouse_files):
        raise ValueError("Wheelhouse input must contain only regular top-level wheels")
    frontend_files = _source_files(frontend)
    if any(part == ".env" or part.startswith(".env.")
           for file in frontend_files for part in file.relative_to(frontend).parts):
        raise ValueError("Frontend input contains an environment file")
    for name in ("native-release.json", ".next/BUILD_ID", "start.mjs", "server.js", "package.json"):
        if not (frontend / name).is_file():
            raise ValueError("Frontend input is not a complete standalone package")
    runtime_manifest = json.loads((runtime / "backend-runtime.json").read_text())
    frontend_manifest = json.loads((frontend / "native-release.json").read_text())
    if runtime_manifest.get("wheel") != wheel.name:
        raise ValueError("Runtime input names a different application wheel")
    environment = runtime_manifest.get("environment", {})
    frontend_build_id = (frontend / ".next/BUILD_ID").read_text().strip()
    manifest = {
        "format_version": "icheck.native-test-release-bundle/v1",
        "name": destination.name,
        "backend_wheel": wheel.name,
        "backend_runtime_manifest": "backend-runtime/backend-runtime.json",
        "backend_constraints": "backend-runtime/backend-constraints.txt",
        "backend_wheelhouse": "backend-wheelhouse", "frontend_package": "frontend",
        "frontend_build_id": frontend_build_id,
        "selected_backend_extras": runtime_manifest.get("extras"),
        "backend_wheel_count": len(wheelhouse_files),
        "selected_runtime": (f"{environment.get('platform_python_implementation')} "
                             f"{environment.get('python_full_version')} on "
                             f"{environment.get('platform_system')} {environment.get('platform_machine')}"),
        "cryptographic_release_signature": False,
        "scope": "Offline application assembly; operator bundle and native/live acceptance remain separate",
    }
    if (frontend_manifest.get("format_version") != "icheck.native-frontend/v1"
            or not frontend_build_id or frontend_manifest.get("build_id") != frontend_build_id):
        raise ValueError("Frontend manifest and build ID differ")
    if frontend_manifest.get("files") != sum(1 for _ in frontend.rglob("*")):
        raise ValueError("Frontend file inventory differs from its manifest")
    api_base = frontend_manifest.get("api_base_url")
    if api_base != "/api/v1":
        try:
            parsed = urlsplit(api_base) if isinstance(api_base, str) else None
            valid = bool(parsed and parsed.scheme == "https" and parsed.hostname
                         and parsed.username is None and parsed.password is None
                         and not parsed.query and not parsed.fragment
                         and parsed.path.endswith("/api/v1"))
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Frontend has an unsafe browser API base")
    destination.mkdir(mode=0o700)
    try:
        shutil.copy2(wheel, destination / wheel.name)
        compared = _equal_files(wheel, destination / wheel.name)
        for source, name, files in (
            (runtime, "backend-runtime", runtime_files),
            (wheelhouse, "backend-wheelhouse", wheelhouse_files),
            (frontend, "frontend", frontend_files),
        ):
            shutil.copytree(source, destination / name)
            for original in files:
                compared += _equal_files(original, destination / name / original.relative_to(source))
        units=repository/"deploy/systemd"
        if include_operator:
            if __package__: from .build_native_test_release import _operator_paths
            else: from build_native_test_release import _operator_paths
            paths=_operator_paths(repository,include_backend_host_preflight=True)
            for relative in paths:
                target=destination/"operator"/relative; target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(repository/relative,target)
                compared+=_equal_files(repository/relative,target)
            manifest.update(format_version="icheck.native-test-release-bundle/v2",operator_root="operator",
                operator_files=paths,operator_file_count=len(paths),
                scope="Offline paired application and operator bundle; native/live acceptance remain separate")
            units=destination/"operator/deploy/systemd"
        (destination / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
        source_wheel_files = assert_wheel_matches_source(destination / wheel.name, repository)
        checked = verify_bundle(destination, units)
        destination.chmod(0o755)
        return {"format_version": "icheck.native-application-assembly/v1",
                "destination": str(destination), "source_wheel_files_byte_compared": source_wheel_files,
                "artifact_bytes_compared": compared, "bundle_check": checked,
                "frontend_build_id": frontend_build_id, "release_ready": False,
                "installed_host_changed": False}
    except BaseException:
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wheel", "runtime", "wheelhouse", "frontend", "repository", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = assemble_application(wheel=args.wheel, runtime=args.runtime, wheelhouse=args.wheelhouse,
        frontend=args.frontend, repository=args.repository, destination=args.out)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
