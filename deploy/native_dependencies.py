"""Pin the installed dependency closure of a native candidate, without URLs."""
from __future__ import annotations

import argparse
from collections import deque
from email.parser import Parser
from importlib import metadata
import json
from pathlib import Path
import sys
from zipfile import ZipFile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version


def resolve_dependencies(requirements, *, extras=(), environment=None, distribution=metadata.distribution):
    environment = environment or default_environment()
    pending = deque()
    versions, selected_extras = {}, {}

    def add(requirements, extras):
        contexts = {"", *extras}
        for raw in requirements:
            requirement = Requirement(raw)
            if requirement.marker is not None and not any(
                requirement.marker.evaluate({**environment, "extra": extra}) for extra in contexts
            ):
                continue
            if requirement.url is not None:
                raise ValueError("Direct dependency URLs cannot become version-only constraints")
            pending.append(requirement)

    add(requirements, extras)
    while pending:
        requirement = pending.popleft()
        name = canonicalize_name(requirement.name)
        installed = distribution(name)
        version = str(Version(installed.version))
        if version not in requirement.specifier:
            raise ValueError(f"Installed dependency does not satisfy its requirement: {name}")
        available = {canonicalize_name(value) for value in installed.metadata.get_all("Provides-Extra", [])}
        requested = {canonicalize_name(value) for value in requirement.extras}
        if requested - available:
            raise ValueError(f"Installed dependency lacks a requested extra: {name}")
        prior = selected_extras.get(name)
        combined = (prior or set()) | requested
        if prior is not None and combined == prior:
            continue
        versions[name], selected_extras[name] = version, combined
        add(installed.requires or [], combined)
    return dict(sorted(versions.items()))


def candidate_manifest(wheel, *, extras=(), distribution=metadata.distribution):
    environment = default_environment()
    with ZipFile(wheel) as archive:
        entries = [entry for entry in archive.infolist() if entry.filename.endswith(".dist-info/METADATA")]
        if len(entries) != 1 or entries[0].file_size > 1_048_576:
            raise ValueError("Candidate must have one bounded wheel metadata document")
        package = Parser().parsestr(archive.read(entries[0]).decode("utf-8"))
    if canonicalize_name(package.get("Name", "")) != "icheck":
        raise ValueError("Candidate must be an iCheck wheel")
    version = str(Version(package["Version"]))
    requires_python = package.get("Requires-Python")
    if requires_python and environment["python_full_version"] not in SpecifierSet(requires_python):
        raise ValueError("Candidate does not support the verification Python")
    selected = {canonicalize_name(extra) for extra in extras}
    available = {canonicalize_name(extra) for extra in package.get_all("Provides-Extra", [])}
    if selected - available or "dev" in selected:
        raise ValueError("Select declared runtime extras, not development dependencies")
    dependencies = resolve_dependencies(package.get_all("Requires-Dist", []), extras=selected,
        environment=environment, distribution=distribution)
    if "icheck" in dependencies:
        raise ValueError("Candidate cannot depend on another installed iCheck distribution")
    return {"format_version": "icheck.native-runtime-constraints/v1", "wheel": Path(wheel).name,
        "project": "icheck", "version": version, "extras": sorted(selected),
        "unselected_extras": sorted(available - selected), "environment": environment,
        "dependencies": dependencies, "clean_install_verified": False,
        "scope": "Installed runtime version pins, not source provenance, artifact signatures or cross-platform compatibility"}


def write_candidate(manifest, destination):
    destination = Path(destination)
    # Claim a new directory only after the entire dependency closure validates.
    # Never overwrite another release or delete its content on a failed write.
    destination.mkdir(parents=True, exist_ok=False)
    with (destination / "backend-constraints.txt").open("x", encoding="utf-8") as output:
        output.write("# Verified installed runtime versions; use only with the recorded wheel, extras and environment.\n")
        output.writelines(f"{name}=={version}\n" for name, version in manifest["dependencies"].items())
    with (destination / "backend-runtime.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, indent=2, sort_keys=True)
        output.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--extra", action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        manifest = candidate_manifest(arguments.wheel, extras=arguments.extra)
        write_candidate(manifest, arguments.out)
    except Exception as error:
        # Requirement and package-index errors can contain private URLs.
        print(f"Runtime pin export failed ({type(error).__name__}); no existing release is overwritten.", file=sys.stderr)
        return 1
    print(f"Pinned {len(manifest['dependencies'])} runtime distributions for {manifest['project']} {manifest['version']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
