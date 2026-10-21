"""Build a native self-extracting installer from the published, verified payload.

The r19.28 payload includes the paired N1–N3 application and integration workers.
Third-party system components are downloaded from pinned HTTPS URLs at install.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

APP_SHA256 = '02e9667ea4af0e3c3ddf837542893521f3a8a2d53aadf134c8d05d5f02d8992d'
APP_ROOT = 'icheck-engineering-preview-0-1-0-r19-28-public-linux-amd64'
FILES = {
    'installer/native_installer.py': 'deploy/native_installer.py',
    'installer/verify_native_installation.py': 'deploy/verify_native_installation.py',
    'installer/grafana/native_install.py': 'deploy/grafana/native_install.py',
    'installer/grafana/dashboards.py': 'deploy/grafana/dashboards.py',
    'installer/grafana/grafana-server.service': 'deploy/grafana/grafana-server.service',
    'INSTALLATION.md': 'docs/native-one-command-installer.md',
}


def valid_member(member):
    path = PurePosixPath(member.name)
    if path.is_absolute() or '..' in path.parts or path.parts[0] != APP_ROOT:
        return False
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        return False
    # Current published payload has no symlinks; refuse new archive contracts.
    return not (member.issym() or member.islnk())


def launcher(digest):
    template = '''#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
if [[ "${1:-}" == "--help" ]]; then
  echo "iCheck r19.28 native installer: fresh Ubuntu 24.04 x86_64, systemd, 3 GiB RAM, 10 GiB free."
  echo "Usage: sudo bash $0 [--server-ip IP --monitor-cidr CIDR --password-file ROOT_0600_FILE --yes]"
  echo "Interactive by default. Online dependencies. No Docker; no existing installation upgrades."
  echo "Use --check to verify the embedded payload without installing."
  exit 0
fi
LINE=@LINE@
EXPECTED=@DIGEST@
ACTUAL=$(tail -n +"$LINE" -- "$0" | sha256sum | cut -d ' ' -f 1)
[[ "$ACTUAL" == "$EXPECTED" ]] || { echo "Installer payload checksum failed" >&2; exit 1; }
if [[ "${1:-}" == "--check" ]]; then echo "Embedded payload verified"; exit 0; fi
[[ "$EUID" == 0 ]] || { echo "Run with sudo" >&2; exit 1; }
exec 9>/run/lock/icheck-native-install.lock
flock -n 9 || { echo "Another installer is already running" >&2; exit 1; }
[[ ! -e /opt/icheck && ! -e /etc/icheck && ! -e /var/lib/icheck-installer ]] || { echo "Existing installation or partial state: refusing to overwrite" >&2; exit 1; }
[[ -d /opt && ! -L /opt && $(stat -c %u /opt) == 0 ]] || { echo "Unsafe /opt directory" >&2; exit 1; }
MODE=$(stat -c %a /opt)
(( (8#$MODE & 0022) == 0 )) || { echo "Writable /opt ancestry refused" >&2; exit 1; }
STAGING=$(mktemp -d /opt/icheck-installer.XXXXXXXX)
trap 'echo "Installer interrupted; retained staging: $STAGING" >&2' INT TERM
tail -n +"$LINE" -- "$0" | tar --extract --gzip --no-same-owner --no-same-permissions --directory "$STAGING"
python3 -I -B "$STAGING/installer/native_installer.py" --payload "$STAGING" "$@"
echo "Verified installer payload retained at $STAGING"
exit 0
__ICHECK_PAYLOAD__
'''
    return template.replace('@LINE@', str(len(template.splitlines()) + 1)).replace('@DIGEST@', digest).encode()


def build(application, source, destination):
    if destination.exists():
        raise ValueError('Destination already exists')
    with application.open('rb') as handle:
        if hashlib.file_digest(handle, 'sha256').hexdigest() != APP_SHA256:
            raise ValueError('Application payload does not match the qualified publication')
    with tempfile.TemporaryFile() as payload:
        with tarfile.open(fileobj=payload, mode='w:gz') as target:
            with tarfile.open(application) as archive:
                for member in archive:
                    if not valid_member(member):
                        raise ValueError('Unexpected application archive member')
                    member.uid = member.gid = 0
                    member.uname = member.gname = 'root'
                    member.mode &= ~0o022
                    target.addfile(member, archive.extractfile(member) if member.isfile() else None)
            for name, relative in FILES.items():
                content = (source / relative).read_bytes()
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.uid, info.gid, info.mtime = len(content), 0o644, 0, 0, 0
                target.addfile(info, io.BytesIO(content))
            content = json.dumps({'format': 'icheck.native-installer/v1', 'version': '0.1.0-preview.r19.28',
                'application_release': APP_ROOT, 'application_archive_sha256': APP_SHA256,
                'platform': 'Ubuntu 24.04 x86_64', 'deployment': 'native-systemd',
                'requires_docker': False, 'online_prerequisites': True, 'fresh_host_only': True,
                'start_here': 'INSTALLATION.md', 'administrator': 'admin', 'shared_default_password': False}, indent=2).encode()
            info = tarfile.TarInfo('native-installer.json')
            info.size, info.mode = len(content), 0o644
            target.addfile(info, io.BytesIO(content))
        payload.seek(0)
        digest = hashlib.file_digest(payload, 'sha256').hexdigest()
        payload.seek(0)
        with destination.open('xb') as output:
            output.write(launcher(digest))
            while chunk := payload.read(1024 * 1024):
                output.write(chunk)
        destination.chmod(0o755)
    return {'path': str(destination), 'embedded_sha256': digest,
            'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(), 'bytes': destination.stat().st_size}


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.application, args.source, args.out)))
