"""Refresh explicit application or operator files in a verified v2 test release.

Applications and every unselected operator file are copied and compared
byte-for-byte. The source bundle is never modified and no SHA inventory is
created. A new output directory and explicit replacement list are required.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
from urllib.parse import urlsplit

if __package__:
    from .build_native_test_release import _equal_files, _source_files
    from .verify_native_backend_bundle import verify_bundle
    from .wheel_source_gate import assert_wheel_matches_source as _assert_wheel_matches_source
else:
    from build_native_test_release import _equal_files, _source_files
    from verify_native_backend_bundle import verify_bundle
    from wheel_source_gate import assert_wheel_matches_source as _assert_wheel_matches_source


def refresh_release(source_arg: Path, destination_arg: Path, repository_arg: Path,
                    replacements: list[str], *, product_wheel_arg: Path | None = None,
                    frontend_package_arg: Path | None = None, refresh_preview_docs: bool = False) -> dict:
    if not all(path.is_absolute() for path in (source_arg, destination_arg, repository_arg)):
        raise ValueError("Release refresh requires absolute source, destination and repository paths")
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
    if (not replacements and product_wheel_arg is None and frontend_package_arg is None
            or len(replacements) != len(set(replacements))):
        raise ValueError("Specify a wheel, frontend package or unique operator files to refresh")
    original = json.loads((source / "release.json").read_text(encoding="utf-8"))
    if original.get("format_version") != "icheck.native-test-release-bundle/v2":
        raise ValueError("Release refresh requires a verified v2 bundle")
    verify_bundle(source, source / "operator/deploy/systemd")
    product_wheel = None
    if product_wheel_arg is not None:
        if (not product_wheel_arg.is_absolute() or product_wheel_arg.is_symlink() or
                not product_wheel_arg.is_file() or
                product_wheel_arg.name != original.get("backend_wheel")):
            raise ValueError("Replacement wheel must be a real absolute file matching the bundle wheel name")
        product_wheel = product_wheel_arg.resolve()
    effective_wheel = product_wheel or source / original["backend_wheel"]
    effective_wheel_source_files = _assert_wheel_matches_source(
        effective_wheel, repository,
    )
    frontend_package = None
    frontend_files: list[Path] = []
    frontend_build_id = original.get("frontend_build_id")
    if frontend_package_arg is not None:
        if (not frontend_package_arg.is_absolute() or frontend_package_arg.is_symlink()
                or not frontend_package_arg.is_dir()):
            raise ValueError("Replacement frontend must be a real absolute directory")
        frontend_package = frontend_package_arg.resolve()
        if (frontend_package == destination or frontend_package in destination.parents
                or destination in frontend_package.parents):
            raise ValueError("Release output must be separate from the frontend package")
        frontend_files = _source_files(frontend_package)
        if any(part == ".env" or part.startswith(".env.")
               for path in frontend_files for part in path.relative_to(frontend_package).parts):
            raise ValueError("Replacement frontend contains an environment file")
        required = ("native-release.json", ".next/BUILD_ID", "start.mjs", "server.js", "package.json")
        if any(not (frontend_package / name).is_file() for name in required):
            raise ValueError("Replacement frontend is not a complete standalone package")
        frontend_manifest = json.loads((frontend_package / "native-release.json").read_text(encoding="utf-8"))
        frontend_build_id = (frontend_package / ".next/BUILD_ID").read_text(encoding="utf-8").strip()
        if (frontend_manifest.get("format_version") != "icheck.native-frontend/v1"
                or not frontend_build_id
                or frontend_manifest.get("build_id") != frontend_build_id):
            raise ValueError("Replacement frontend manifest and build ID differ")
        api_base = frontend_manifest.get("api_base_url")
        if api_base != "/api/v1":
            try:
                parsed = urlsplit(api_base) if isinstance(api_base, str) else None
                valid_api = bool(
                    parsed and parsed.scheme == "https" and parsed.hostname
                    and parsed.username is None and parsed.password is None
                    and not parsed.query and not parsed.fragment
                    and parsed.path.endswith("/api/v1")
                )
            except ValueError:
                valid_api = False
            if not valid_api:
                raise ValueError("Replacement frontend has an unsafe browser API base")
        if frontend_manifest.get("files") != sum(1 for _ in frontend_package.rglob("*")):
            raise ValueError("Replacement frontend file inventory differs from its manifest")
    declared = set(original["operator_files"])
    for name in replacements:
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or "." in path.parts or
                path.as_posix() != name or name not in declared or
                not (repository / name).is_file() or (repository / name).is_symlink()):
            raise ValueError(f"Operator replacement is missing or undeclared: {name}")
    source_files = _source_files(source)
    destination.mkdir(mode=0o700)
    try:
        for child in source.iterdir():
            if child.name == "release.json" or (frontend_package is not None and child.name == "frontend"):
                continue
            target = destination / child.name
            if child.is_dir():
                shutil.copytree(child, target, symlinks=True)
            elif child.is_file() and not child.is_symlink():
                shutil.copy2(child, target)
            else:
                raise ValueError("Release source contains a non-regular top-level entry")
        if frontend_package is not None:
            shutil.copytree(frontend_package, destination / "frontend", symlinks=True)
        changed: list[str] = []
        wheel_changed = False
        if product_wheel is not None:
            try:
                _equal_files(source / original["backend_wheel"], product_wheel)
            except ValueError:
                wheel_changed = True
            shutil.copy2(product_wheel, destination / original["backend_wheel"])
        for name in replacements:
            old = source / "operator" / name
            new = repository / name
            try:
                _equal_files(old, new)
            except ValueError:
                changed.append(name)
            shutil.copy2(new, destination / "operator" / name)
        bytes_compared = 0
        inherited_files = 0
        for old in source_files:
            relative = old.relative_to(source)
            if relative == Path("release.json") or (
                product_wheel is not None and relative == Path(original["backend_wheel"])
            ) or (
                frontend_package is not None and relative.parts[0] == "frontend"
            ) or (
                relative.parts[0] == "operator" and relative.as_posix()[len("operator/"):] in replacements
            ):
                continue
            bytes_compared += _equal_files(old, destination / relative)
            inherited_files += 1
        for name in replacements:
            bytes_compared += _equal_files(repository / name, destination / "operator" / name)
        if product_wheel is not None:
            bytes_compared += _equal_files(product_wheel, destination / original["backend_wheel"])
        if frontend_package is not None:
            for path in frontend_files:
                bytes_compared += _equal_files(path, destination / "frontend" / path.relative_to(frontend_package))
        # Recheck the copied candidate against source after all refresh I/O.
        # A source or wheel change during the copy must not leave a stale release.
        effective_wheel_source_files = _assert_wheel_matches_source(
            destination / original["backend_wheel"], repository,
        )
        refreshed_docs = []
        if refresh_preview_docs:
            if __package__:
                from .build_engineering_preview import PREVIEW_FILES
            else:
                from build_engineering_preview import PREVIEW_FILES
            for relative in sorted(name for name in PREVIEW_FILES if name.startswith("docs/")):
                source_doc = repository / PREVIEW_FILES[relative]
                target_doc = destination / relative
                if source_doc.is_symlink() or not source_doc.is_file() or not target_doc.is_file():
                    raise ValueError("Required preview document is missing or linked")
                shutil.copy2(source_doc, target_doc)
                _equal_files(source_doc, target_doc)
                refreshed_docs.append(relative)
        manifest = {**original, "name": destination.name, "frontend_build_id": frontend_build_id}
        (destination / "release.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                                  encoding="utf-8")
        checked = verify_bundle(destination, destination / "operator/deploy/systemd")
        destination.chmod(0o755)
        return {"format_version": "icheck.native-test-release-refresh/v1",
                "destination": str(destination), "inherited_files_byte_compared": inherited_files,
                "preview_docs_refreshed": refreshed_docs,
                "operator_files_replaced": replacements, "operator_files_changed": changed,
                "application_wheel_replaced": product_wheel is not None,
                "application_wheel_changed": wheel_changed,
                "effective_wheel_source_files": effective_wheel_source_files,
                "replacement_wheel_source_files": (
                    effective_wheel_source_files if product_wheel is not None else None
                ),
                "frontend_package_replaced": frontend_package is not None,
                "frontend_build_id": frontend_build_id,
                "frontend_files_byte_compared": len(frontend_files),
                "bytes_compared": bytes_compared, "bundle_check": checked["format_version"],
                "release_ready": False}
    except BaseException:
        shutil.rmtree(destination)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--replace-operator", action="append", default=[])
    parser.add_argument("--replace-wheel", type=Path)
    parser.add_argument("--replace-frontend", type=Path)
    parser.add_argument("--refresh-preview-docs", action="store_true")
    args = parser.parse_args()
    result = refresh_release(args.source, args.out, args.repository, args.replace_operator,
                             product_wheel_arg=args.replace_wheel,
                             frontend_package_arg=args.replace_frontend, refresh_preview_docs=args.refresh_preview_docs)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
