"""Verify one Linux native backend bundle without a digest or database access."""

from __future__ import annotations

import argparse
import configparser
from email.parser import BytesParser
import json
from pathlib import Path
import platform
import re
import sys
from zipfile import BadZipFile, ZipFile

from packaging.requirements import Requirement
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

EXTERNAL_UNITS = {
    "icheck-frontend.service": "/opt/icheck/node/bin/node",
    "icheck-prometheus.service": "/opt/icheck/bin/prometheus",
    "icheck-snmp-exporter.service": "/opt/icheck/bin/snmp_exporter",
}
OPTIONAL_NATIVE_UNITS = {
    "icheck-alertmanager.service": "/opt/icheck/bin/alertmanager",
    "icheck-snmp-module-installer.service": "/opt/icheck/.venv/bin/python -I -m icheck.snmp_install_broker",
}
REQUIRED_PYTHON_UNITS = {
    "icheck-agent-capacity@.service", "icheck-agent-worker.service",
    "icheck-ansible-adapter.service", "icheck-collector-capacity@.service",
    "icheck-collector-lease-reconciler.service", "icheck-collector.service",
    "icheck-control-plane.service", "icheck-ecosystem-transport-worker.service",
    "icheck-indicator-worker.service", "icheck-mcp-attestor.service",
    "icheck-projection-worker.service", "icheck-quality-worker.service",
    "icheck-rollout-worker.service", "icheck-scaling-worker.service",
    "icheck-snmp-attestor@.service", "icheck-systemd-capacity-provider.service",
    "icheck-workflow-dispatch-worker.service",
    "icheck-monitoring-gateway.service",
}
OPERATOR_TOOLS = {
    "deploy/verify_native_backend_bundle.py",
    "deploy/stage_native_backend.py",
    "deploy/switch_native_backend.py",
    "deploy/native_frontend_permissions.mjs",
    "deploy/stage_native_frontend.mjs",
    "deploy/switch_native_frontend.mjs",
    "deploy/check_native_frontend_host.mjs",
    "frontend/scripts/native-package.mjs",
}
OPERATOR_CONFIGURATION = {
    "deploy/systemd/monitoring-gateway.config.json.example",
    "deploy/prometheus/gui-continuous.yml.example",
}


def _verify_operator_tree(bundle: Path, release: dict, units: Path) -> int:
    operator = bundle / "operator"
    if operator.is_symlink() or not operator.is_dir():
        raise ValueError("Self-contained release is missing a real operator directory")
    files: set[str] = set()
    allowed_dirs = {"", "deploy", "deploy/systemd", "deploy/prometheus", "frontend", "frontend/scripts"}
    for path in operator.rglob("*"):
        name = path.relative_to(operator).as_posix()
        if path.is_symlink():
            raise ValueError("Self-contained operator tree contains a symlink")
        if path.is_dir():
            if name not in allowed_dirs:
                raise ValueError("Self-contained operator tree contains an unexpected directory")
        elif path.is_file():
            files.add(name)
        else:
            raise ValueError("Self-contained operator tree contains a non-regular entry")
    recorded = release.get("operator_files")
    if not isinstance(recorded, list) or recorded != sorted(files) or len(recorded) != len(files):
        raise ValueError("Self-contained operator file inventory differs from its manifest")
    required = OPERATOR_TOOLS | OPERATOR_CONFIGURATION | {
        f"deploy/systemd/{name}" for name in REQUIRED_PYTHON_UNITS | set(EXTERNAL_UNITS)
    }
    if not required.issubset(files):
        raise ValueError("Self-contained release is missing a required operator tool or service unit")
    if (release.get("operator_root") != "operator" or
            release.get("operator_file_count") != len(files) or
            units.resolve() != (operator / "deploy/systemd").resolve()):
        raise ValueError("Self-contained release must verify its own operator unit templates")
    return len(files)


def _wheel_metadata(path: Path) -> tuple[str, Version]:
    with ZipFile(path) as archive:
        metadata_paths = [name for name in archive.namelist()
                          if name.endswith(".dist-info/METADATA") and name.count("/") == 1]
        if len(metadata_paths) != 1:
            raise ValueError(f"{path.name}: exactly one wheel METADATA file is required")
        if archive.testzip() is not None:
            raise ValueError(f"{path.name}: wheel archive failed its ZIP integrity check")
        metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
        if not metadata.get("Name") or not metadata.get("Version"):
            raise ValueError(f"{path.name}: wheel metadata is missing name or version")
        return canonicalize_name(metadata["Name"]), Version(metadata["Version"])


def _constraints(path: Path) -> dict[str, Version]:
    pinned: dict[str, Version] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        specifiers = list(requirement.specifier)
        if (requirement.extras or requirement.marker or requirement.url or len(specifiers) != 1
                or specifiers[0].operator != "==" or "*" in specifiers[0].version):
            raise ValueError("Runtime constraints must contain only exact version pins")
        name = canonicalize_name(requirement.name)
        if name in pinned:
            raise ValueError(f"Runtime constraints repeat {name}")
        pinned[name] = Version(specifiers[0].version)
    if not pinned:
        raise ValueError("Runtime constraints contain no dependency pins")
    return pinned


def _product_scripts(path: Path) -> set[str]:
    with ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/entry_points.txt")]
        if len(names) != 1:
            raise ValueError("Product wheel must contain one entry-point list")
        config = configparser.ConfigParser()
        config.read_string(archive.read(names[0]).decode("utf-8"))
        return set(config["console_scripts"])


def selected_backend_extras(manifest: dict) -> list[str]:
    extras = manifest.get("extras")
    if extras not in (["windows"], ["extensions", "windows"]) or "action" not in manifest.get("unselected_extras", []):
        raise ValueError("Backend extras must select the reviewed native runtime, without action or development extras")
    return extras


def verify_bundle(bundle: Path, units: Path) -> dict:
    bundle = bundle.resolve()
    for member in ("release.json", "backend-runtime/backend-runtime.json",
                   "backend-runtime/backend-constraints.txt", "frontend/native-release.json",
                   "frontend/.next/BUILD_ID"):
        if (bundle / member).is_symlink():
            raise ValueError(f"Native release member is a symlink: {member}")
    release = json.loads((bundle / "release.json").read_text(encoding="utf-8"))
    format_version = release.get("format_version")
    if (format_version not in {"icheck.native-test-release-bundle/v1",
                               "icheck.native-test-release-bundle/v2"}
            or release.get("name") != bundle.name
            or release.get("backend_runtime_manifest") != "backend-runtime/backend-runtime.json"
            or release.get("backend_constraints") != "backend-runtime/backend-constraints.txt"
            or release.get("backend_wheelhouse") != "backend-wheelhouse"
            or release.get("frontend_package") != "frontend"):
        raise ValueError("Native release manifest does not name this bundle's fixed artifacts")
    operator_files = 0
    if format_version.endswith("/v2"):
        operator_files = _verify_operator_tree(bundle, release, units)
    manifest = json.loads((bundle / "backend-runtime" / "backend-runtime.json").read_text(encoding="utf-8"))
    if manifest.get("format_version") != "icheck.native-runtime-constraints/v1":
        raise ValueError("Unsupported backend runtime manifest")
    environment = manifest.get("environment", {})
    actual = {
        "implementation_name": sys.implementation.name,
        "implementation_version": platform.python_version(),
        "platform_machine": platform.machine(),
        "platform_system": platform.system(),
        "python_full_version": platform.python_version(),
        "sys_platform": sys.platform,
    }
    if any(environment.get(key) != value for key, value in actual.items()):
        raise ValueError("Backend wheelhouse was selected for a different Python or platform")
    selected_backend_extras(manifest)
    expected_runtime = (f"{environment['platform_python_implementation']} "
                        f"{environment['python_full_version']} on "
                        f"{environment['platform_system']} {environment['platform_machine']}")
    if (release.get("selected_backend_extras") != manifest["extras"]
            or release.get("selected_runtime") != expected_runtime
            or release.get("cryptographic_release_signature") is not False):
        raise ValueError("Native release manifest overstates or changes the selected runtime")

    pinned = _constraints(bundle / "backend-runtime" / "backend-constraints.txt")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ValueError("Runtime manifest dependency map is invalid")
    recorded = {canonicalize_name(name): Version(version)
                for name, version in dependencies.items()}
    if pinned != recorded:
        raise ValueError("Runtime manifest and constraints differ")
    wheel_name = manifest.get("wheel")
    if not isinstance(wheel_name, str) or Path(wheel_name).name != wheel_name:
        raise ValueError("Runtime manifest has an invalid product wheel name")
    product = bundle / wheel_name
    if release.get("backend_wheel") != wheel_name:
        raise ValueError("Native release and runtime manifests name different product wheels")
    if product.is_symlink() or not product.is_file():
        raise ValueError("Product wheel must be a regular file inside the bundle")
    product_name, product_version, _, product_tags = parse_wheel_filename(product.name)
    if (product_name != canonicalize_name(manifest.get("project", ""))
            or product_version != Version(manifest.get("version", "0"))
            or not product_tags.intersection(set(sys_tags()))
            or _wheel_metadata(product) != (product_name, product_version)):
        raise ValueError("Product wheel name, metadata, platform or runtime manifest differs")
    scripts = _product_scripts(product)

    expected_tags = set(sys_tags())
    wheelhouse = bundle / "backend-wheelhouse"
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ValueError("Backend wheelhouse must be a real directory")
    files = sorted(wheelhouse.iterdir())
    if not files or any(path.is_symlink() or not path.is_file() or path.suffix != ".whl" for path in files):
        raise ValueError("Backend wheelhouse must contain only regular wheel files")
    seen: dict[str, Version] = {}
    for path in files:
        name, version, _, tags = parse_wheel_filename(path.name)
        if name in seen:
            raise ValueError(f"Backend wheelhouse repeats {name}")
        if name not in pinned or pinned[name] != version or not tags.intersection(expected_tags):
            raise ValueError(f"{path.name}: wheel is unpinned or incompatible with this runtime")
        if _wheel_metadata(path) != (name, version):
            raise ValueError(f"{path.name}: wheel metadata differs from its filename")
        seen[name] = version
    if seen != pinned:
        missing = sorted(set(pinned) - set(seen))
        raise ValueError(f"Backend wheelhouse is missing {len(missing)} pinned distributions")
    if release.get("backend_wheel_count") != len(files):
        raise ValueError("Native release manifest wheel count differs from the wheelhouse")

    frontend = bundle / "frontend"
    if frontend.is_symlink() or not frontend.is_dir():
        raise ValueError("Frontend package must be a real directory inside the bundle")
    frontend_manifest = json.loads((frontend / "native-release.json").read_text(encoding="utf-8"))
    frontend_build = (frontend / ".next" / "BUILD_ID").read_text(encoding="utf-8").strip()
    if (frontend_manifest.get("format_version") != "icheck.native-frontend/v1"
            or frontend_manifest.get("build_id") != frontend_build
            or release.get("frontend_build_id") != frontend_build):
        raise ValueError("Native release and frontend manifests name different builds")

    unit_paths = sorted(units.glob("icheck-*.service"))
    names={unit.name for unit in unit_paths}
    required=REQUIRED_PYTHON_UNITS | set(EXTERNAL_UNITS)
    if not required.issubset(names) or names-required-set(OPTIONAL_NATIVE_UNITS):
        raise ValueError("Native systemd service template set differs from the selected release")
    python_units = []
    external_units = []
    optional_units = []
    for unit in unit_paths:
        content = unit.read_text(encoding="utf-8")
        matches = re.findall(r"^ExecStart=(\S+)", content, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(f"{unit.name}: exactly one ExecStart is required")
        command = matches[0]
        prefix = "/opt/icheck/.venv/bin/"
        if unit.name in OPTIONAL_NATIVE_UNITS:
            expected=OPTIONAL_NATIVE_UNITS[unit.name]
            if unit.name=="icheck-snmp-module-installer.service":
                starts=re.findall(r"^ExecStart=(.+)$",content,re.MULTILINE)
                if starts!=[expected]: raise ValueError("SNMP installer requires its fixed isolated native module command")
                with ZipFile(product) as archive:
                    if "icheck/snmp_install_broker.py" not in archive.namelist():
                        raise ValueError("SNMP installer module is absent from the installed wheel")
            elif command!=expected:
                raise ValueError(f"{unit.name}: ExecStart is outside the native release contract")
            optional_units.append(unit.name)
        elif unit.name in REQUIRED_PYTHON_UNITS and command.startswith(prefix):
            script = command.removeprefix(prefix)
            if script not in scripts and script != "uvicorn":
                raise ValueError(f"{unit.name}: {script} is absent from the installed wheel")
            if script == "uvicorn" and "uvicorn" not in pinned:
                raise ValueError("API unit requires an unpinned uvicorn runtime")
            python_units.append(unit.name)
        elif (EXTERNAL_UNITS.get(unit.name) == command or
              # Retained pre-r24 artifacts used the global Node path. This
              # permits historical bundle reads, not a host-version waiver:
              # current cutover guards require the dedicated native path.
              (unit.name == "icheck-frontend.service" and command == "/usr/bin/node")):
            external_units.append(unit.name)
        else:
            raise ValueError(f"{unit.name}: ExecStart is outside the native release contract")
    return {
        "format_version": ("icheck.native-backend-bundle-check/v2" if operator_files
                           else "icheck.native-backend-bundle-check/v1"),
        "product_wheel": product.name,
        "frontend_build_id": frontend_build,
        "pinned_binary_wheels": len(files),
        "product_console_scripts": len(scripts),
        "python_unit_templates": len(python_units),
        "external_unit_templates": len(external_units),
        "optional_native_unit_templates": optional_units,
        "selected_extras": manifest["extras"],
        "optional_action_runtime_included": False,
        "operator_files": operator_files,
        "passed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("units", type=Path)
    args = parser.parse_args()
    try:
        result = verify_bundle(args.bundle, args.units)
    except (BadZipFile, OSError, KeyError, ValueError) as error:
        parser.exit(1, f"Native backend bundle check failed: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
