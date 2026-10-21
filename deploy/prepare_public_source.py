"""Export application source without runtime state or private deployment evidence.

This deliberately excludes host-specific operations scripts and acceptance
receipts. It does not sanitize arbitrary secrets: scan and review the resulting
tree and built archives before publishing. Never execute the export on a host.
"""
import argparse
import json
from pathlib import Path
import re
import shutil

ROOT_FILES = {
    '.dockerignore', '.env.example', '.gitignore', 'Dockerfile', 'README.md',
    'alembic.ini', 'docker-compose.yml', 'iCheck_project_design.md', 'pyproject.toml',
    'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md',
    'acceptance/public-preview-qualification.json',
}
ROOT_DIRECTORIES = {'backend', 'frontend', 'tests', 'deploy', 'docs', '.github'}
OMIT_PARTS = {'node_modules', '__pycache__', '.next', '.venext', '.vinext', '.wrangler',
    '.sites-runtime', '.pytest_cache', '.ruff_cache', 'dist', '.git', '.venv',
    '.playwright-cli', 'playwright-report', 'test-results'}
PRIVATE_TOOLS = {
    'upgrade_engineering_preview.py', 'check_multi_provider_deployment.py',
    'verify_multi_provider_http.py', 'preview_browser_session.py',
    'prepare_openrouter_r11_browser.mjs', 'provision_preview_monitoring.py',
    'sync_native_grafana_tool.py', 'preview_investigation_dispatch.py',
    'preview_monitoring_integrations.py', 'check_n1_n3_deployment.py',
    'verify_n1_n3_http.py',
}


def export(repository: Path, destination: Path):
    repository = repository.resolve()
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValueError('Use a new absolute export directory')
    destination.mkdir(parents=True)
    copied = []
    for root in sorted(ROOT_FILES | ROOT_DIRECTORIES):
        base = repository/root
        if not base.exists():
            continue
        for path in ([base] if base.is_file() else sorted(base.rglob('*'))):
            relative = path.relative_to(repository)
            if (not path.is_file() or path.is_symlink() or set(relative.parts) & OMIT_PARTS
                    or any(part.endswith('.egg-info') for part in relative.parts)
                    or str(relative).startswith('deploy/runtime/')
                    or path.name == 'next-env.d.ts'
                    or (path.name.startswith('.env') and path.name != '.env.example')
                    or path.suffix in {'.pyc', '.pyo', '.db', '.sqlite', '.sqlite3', '.tsbuildinfo', '.log'}):
                continue
            if relative.parts[0] == 'deploy' and (
                path.name in PRIVATE_TOOLS or re.search(r'_r\d+', path.name)
                or path.name.endswith('_browser_mock.js')):
                continue
            target = destination/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
            copied.append(str(relative))
    print(json.dumps({'files_exported': len(copied), 'runtime_state_exported': False,
        'private_acceptance_receipts_exported': False, 'destination': str(destination)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    export(args.repository, args.out)
