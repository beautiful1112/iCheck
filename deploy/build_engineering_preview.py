"""Package a source-verified native application with Preview v0.1 operator guides.

No downloads, installations, database changes or service starts. Existing
destinations are never overwritten. Preview documentation lives outside the
strict operator tree, preserving the existing installer verification contract.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from zipfile import ZipFile

if __package__:
    from .build_native_test_release import build_release, _equal_files
    from .stage_native_backend import RELEASE_ID
else:
    from build_native_test_release import build_release, _equal_files
    from stage_native_backend import RELEASE_ID

PREVIEW_FILES = {
    "README.md": "README.md",
    "SECURITY.md": "SECURITY.md",
    "tools/preview_smoke.py": "deploy/preview_smoke.py",
    "tools/preview_operator_password.py": "deploy/preview_operator_password.py",
    "tools/preview_managed_ai.py": "deploy/preview_managed_ai.py",
    "tools/preview_lab_demo.py": "deploy/preview_lab_demo.py",
    "tools/preview_native_access.py": "deploy/preview_native_access.py",
    "tools/preview_native_ingress.py": "deploy/preview_native_ingress.py",
    "tools/preview_native_monitoring.py": "deploy/preview_native_monitoring.py",
    "config/nginx.service": "deploy/preview/nginx.service",
    "acceptance/public-preview-qualification.json": "acceptance/public-preview-qualification.json",
    **{f"docs/{name}.md": f"docs/{name}.md" for name in (
        "engineering-preview-installation", "engineering-preview-quick-start",
        "engineering-preview-known-limitations", "engineering-preview-server-access", "development-plan",
        "native-release", "agent-runtime",
        "control-plane-auth", "worker-mtls", "tenant-region-isolation",
        "continuous-monitoring", "prometheus-snmp-rollout", "ai-provider-configuration", "ai-multi-provider-setup",
        "device-onboarding", "workflow-templates", "collector-contracts",
        "topology-views", "metric-query-authorization",
        "grafana-access", "grafana-monitoring-design", "capability-studio",
        "http-monitoring", "system-exporter-monitoring", "container-monitoring",
        "vmware-monitoring", "metric-alerts", "tool-skill-designer",
        "snmp-exporter-attestation",
    )},
    **{f"config/alertmanager/{name}":f"deploy/alertmanager/{name}" for name in (
        "alertmanager.yml.example","prometheus-alerting.yml.example","rules.yml.example","control-plane.env.example")},
}


def package_preview(source: Path | None, destination: Path, repository: Path,*,artifacts:dict | None=None) -> dict:
    if not all(path.is_absolute() for path in (destination, repository,*([source] if source is not None else []))):
        raise ValueError("Preview packaging requires absolute paths")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Preview destination already exists; refusing to overwrite")
    if not RELEASE_ID.fullmatch(destination.name) or destination.name == "none":
        raise ValueError("Preview destination name is not a valid native release ID")
    for relative in PREVIEW_FILES.values():
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Preview input is missing or linked: {relative}")
    if source is not None and artifacts is None:
        result = build_release(source, destination, repository, include_backend_host_preflight=True)
    elif source is None and artifacts is not None:
        if __package__: from .assemble_native_application import assemble_application
        else: from assemble_native_application import assemble_application
        result=assemble_application(**artifacts,repository=repository,destination=destination,include_operator=True)
    else:
        raise ValueError("Choose an existing application assembly or explicit current artifacts, not both")
    try:
        for target, original in PREVIEW_FILES.items():
            path = destination / target
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repository / original, path)
            _equal_files(repository / original, path)
        native = json.loads((destination / "release.json").read_text())
        with ZipFile(destination / native["backend_wheel"]) as archive:
            migration_files = sorted(name for name in archive.namelist()
                                     if name.startswith("migrations/versions/") and name.endswith(".py"))
        manifest = {
            "format_version": "icheck.engineering-preview/v1", "version": "0.1.0",
            "name": destination.name, "deployment": "native-single-node",
            "application_manifest": "release.json",
            "start_here": "docs/engineering-preview-installation.md",
            "quick_start": "docs/engineering-preview-quick-start.md",
            "known_limitations": "docs/engineering-preview-known-limitations.md",
            "candidate_qualification": "acceptance/public-preview-qualification.json",
            "feedback_url": "https://github.com/beautiful1112/iCheck/issues",
            "tools": ["tools/preview_smoke.py", "tools/preview_lab_demo.py"],
            "native_setup_tools": ["tools/preview_native_access.py", "tools/preview_native_ingress.py", "tools/preview_native_monitoring.py", "tools/preview_managed_ai.py"],
            "evaluation_ingress_unit": "config/nginx.service",
            "reference_deployment_scope": "No private host deployment records are distributed; verify your own installation",
            "preview_files": sorted(PREVIEW_FILES),
            "frontend_build_id": native["frontend_build_id"],
            "backend_migration_files": len(migration_files),
            "application_source_verified": True, "default_infrastructure_operations": "read-only",
            "native_host_installation_verified": False, "user_lab_acceptance": "pending",
            "production_ready": False, "cryptographic_release_signature": False,
        }
        (destination / "preview.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return {**result, "preview_manifest": "preview.json", "preview_files": len(PREVIEW_FILES),
                "installed_host_changed": False, "user_lab_acceptance": "pending"}
    except BaseException:
        # build_release exclusively claimed this destination. Never touch inputs
        # or an existing release on failure.
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source", type=Path, help="Verified v1 application assembly")
    mode.add_argument("--wheel",type=Path,help="Current wheel; direct mode copies application artifacts only once")
    for name in ("runtime","wheelhouse","frontend"): parser.add_argument("--"+name,type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if args.source is not None:
        if any(getattr(args,name) for name in ("runtime","wheelhouse","frontend")): parser.error("--source cannot be combined with current artifact inputs")
        result=package_preview(args.source,args.out,args.repository)
    else:
        if not all(getattr(args,name) for name in ("wheel","runtime","wheelhouse","frontend")): parser.error("Direct mode requires --wheel, --runtime, --wheelhouse and --frontend")
        result=package_preview(None,args.out,args.repository,artifacts={name:getattr(args,name) for name in ("wheel","runtime","wheelhouse","frontend")})
    print(json.dumps(result,sort_keys=True))


if __name__ == "__main__":
    main()
