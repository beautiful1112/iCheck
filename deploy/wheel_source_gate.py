"""Byte-compare a native release wheel with current backend and migration source."""

from __future__ import annotations

from pathlib import Path
from zipfile import BadZipFile, ZipFile


def assert_wheel_matches_source(wheel: Path, repository: Path) -> int:
    """Compare member names and bytes directly; do not create a hash inventory."""
    roots = {
        "icheck": repository / "backend/icheck",
        "migrations": repository / "backend/migrations",
    }
    if any(not root.is_dir() or root.is_symlink() for root in roots.values()):
        raise ValueError("Release repository is missing backend or migration source")
    if any(path.is_symlink() for root in roots.values() for path in root.rglob("*")):
        raise ValueError("Release backend source contains a symlink")
    sources = {
        f"{archive_root}/{file.relative_to(source_root).as_posix()}": file
        for archive_root, source_root in roots.items()
        for file in source_root.rglob("*")
        if file.is_file()
        and "__pycache__" not in file.parts
        and file.suffix not in {".pyc", ".pyo"}
        and file.name != ".gitkeep"
    }
    if not sources or any(path.is_symlink() for path in sources.values()):
        raise ValueError("Release backend source is empty or contains a symlink")
    if wheel.is_symlink() or not wheel.is_file():
        raise ValueError("Release wheel must be a real file")
    try:
        with ZipFile(wheel) as archive:
            names = [
                name for name in archive.namelist()
                if not name.endswith("/")
                and any(name.startswith(f"{root}/") for root in roots)
            ]
            if len(names) != len(set(names)):
                raise ValueError("Release wheel contains duplicate backend members")
            packaged = set(names)
            if set(sources) != packaged:
                raise ValueError(
                    "Release wheel backend source inventory differs from repository "
                    f"(missing={len(set(sources) - packaged)}, extra={len(packaged - set(sources))})"
                )
            different = [
                name for name, path in sources.items()
                if archive.read(name) != path.read_bytes()
            ]
    except BadZipFile as exc:
        raise ValueError("Release wheel is not a valid ZIP archive") from exc
    if different:
        raise ValueError(
            f"Release wheel backend source differs from repository ({len(different)} files)"
        )
    return len(sources)
