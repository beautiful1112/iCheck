"""Native, first-install Grafana for the existing iCheck evaluation ingress.

Run a reviewed root-owned copy. Does not replace an installation, modify
Prometheus, reset existing credentials, or create/change device enrollments.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

sys.dont_write_bytecode = True
VERSION = "13.2.3"
ARTIFACT_SHA256 = "6107ad27016296aac38e0d7ffa8753ab540b5541ad27e94790f771289d733235"
CONFIG = Path("/etc/icheck-grafana")
DATA = Path("/var/lib/icheck-grafana")
RELEASES = Path("/opt/icheck/grafana-releases")
ACTIVE = Path("/opt/icheck/grafana")
INGRESS = Path("/etc/icheck-preview-ingress/nginx.conf")
BACKUP = Path("/var/backups/icheck/grafana-first-install")
USER = "icheck-grafana"
UNIT = Path("/etc/systemd/system/grafana-server.service")
USERNAME = "zhao@icheck.preview"


def trusted(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Deployment ancestry is not root-owned and protected")


def run(args, *, timeout=60):
    result = subprocess.run(args, cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Deployment command failed: " + Path(args[0]).name)
    return result.stdout.strip()


def write_new(path, data, *, gid=0, uid=0, mode=0o640):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        os.fchown(handle.fileno(), uid, gid)
        handle.write(data.encode() if isinstance(data, str) else data)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), mode)


def grafana_config(public_url):
    url = urlsplit(public_url)
    if (url.scheme != "https" or not url.hostname or url.username or url.password or
            url.query or url.fragment or url.path != "/grafana/" or
            any(ord(char) < 33 for char in public_url)):
        raise ValueError("Public URL must be credential-free HTTPS ending /grafana/")
    return f"""[paths]
data = /var/lib/icheck-grafana
logs = /var/lib/icheck-grafana/logs
plugins = /var/lib/icheck-grafana/plugins
provisioning = /etc/icheck-grafana/provisioning
[server]
protocol = http
http_addr = 127.0.0.1
http_port = 3001
domain = {url.hostname}
root_url = {public_url}
serve_from_sub_path = true
[database]
type = sqlite3
path = /var/lib/icheck-grafana/grafana.db
[security]
admin_user = {USERNAME}
admin_password = $__file{{/etc/icheck-grafana/initial-admin-password}}
secret_key = $__file{{/etc/icheck-grafana/secret-key}}
cookie_secure = true
cookie_samesite = strict
allow_embedding = false
[users]
allow_sign_up = false
allow_org_create = false
[auth.anonymous]
enabled = false
[auth]
disable_login_form = false
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[plugins]
preinstall_disabled = true
[log]
mode = console
level = warn
[unified_alerting]
enabled = false
"""


GRAFANA_LOCATION = """
        # iCheck-managed Grafana routing; keep all existing API/mTLS routes.
        location = /grafana { return 302 /grafana/; }
        location /grafana/api/live/ {
            proxy_pass http://127.0.0.1:3001;
            proxy_http_version 1.1;
            proxy_set_header Host $host:$server_port;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host $host:$server_port;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header X-WEBAUTH-USER "";
            proxy_read_timeout 60s;
        }
        location /grafana/ {
            proxy_pass http://127.0.0.1:3001;
            proxy_http_version 1.1;
            proxy_set_header Host $host:$server_port;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host $host:$server_port;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Connection "";
            proxy_set_header X-WEBAUTH-USER "";
            proxy_set_header X-Icheck-Bootstrap-Token "";
            proxy_set_header X-Icheck-Trusted-Proxy-Verified "";
            proxy_set_header X-Icheck-Trusted-Proxy-Subject "";
            proxy_set_header X-Icheck-Trusted-Proxy-Secret "";
            proxy_read_timeout 60s;
        }
"""


def ingress_with_grafana(original):
    anchor = "        location / {\n            proxy_pass http://127.0.0.1:3000;"
    if "location /grafana/" in original or original.count(anchor) != 1:
        raise ValueError("Unexpected ingress layout; no replacement performed")
    return original.replace(anchor, GRAFANA_LOCATION + anchor, 1)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api_call(route, *, password, method="GET", data=None):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    auth = base64.b64encode((USERNAME + ":" + password).encode()).decode()
    request = Request("http://127.0.0.1:3001/grafana" + route, method=method,
                      headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"},
                      data=None if data is None else json.dumps(data).encode())
    try:
        with opener.open(request, timeout=30) as response:
            raw = response.read(2 * 1024 * 1024)
            return json.loads(raw) if raw else None
    except HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError("Grafana API returned HTTP " + str(status)) from None


def install(artifact, public_url):
    trusted(Path(__file__).resolve())
    sys.path.insert(0, str(Path(__file__).parent))
    from dashboards import baseline_dashboards
    for path in (CONFIG, DATA, ACTIVE, RELEASES / VERSION, UNIT, BACKUP):
        if path.exists() or path.is_symlink():
            raise ValueError("Existing Grafana installation/custody; first-install refused")
    ini = grafana_config(public_url)
    trusted(INGRESS)
    original = INGRESS.read_text()
    extended = ingress_with_grafana(original)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 3001))
    with artifact.open("rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != ARTIFACT_SHA256:
            raise ValueError("Official Grafana artifact integrity check failed")
        handle.seek(0)
        archive = tarfile.open(fileobj=handle, mode="r:gz")
        members = archive.getmembers()
        prefix = "grafana-" + VERSION
        if (sum(member.size for member in members) > 2 * 1024 ** 3 or
                any(not (member.isfile() or member.isdir()) or
                    not (member.name == prefix or member.name.startswith(prefix + "/"))
                    for member in members)):
            raise ValueError("Unexpected Grafana archive payload")
        if shutil.disk_usage("/opt").free < sum(m.size for m in members) + 1024 ** 3:
            raise ValueError("Need space for Grafana plus 1 GiB reserve")
        RELEASES.mkdir(mode=0o755, exist_ok=True)
        trusted(RELEASES)
        staging = RELEASES / (".install-" + VERSION)
        staging.mkdir(mode=0o700)
        archive.extractall(staging, filter="data")
        home = staging / prefix
        for entry in [home, *home.rglob("*")]:
            os.chown(entry, 0, 0)
            entry.chmod(0o755 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o644)
        os.rename(home, RELEASES / VERSION)
        staging.rmdir()
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
             "--home-dir", "/var/lib/icheck-grafana", "--shell", "/usr/sbin/nologin", USER])
        account = pwd.getpwnam(USER)
    if (account.pw_uid == 0 or account.pw_shell != "/usr/sbin/nologin" or
            os.getgrouplist(USER, account.pw_gid) != [account.pw_gid]):
        raise ValueError("Grafana service identity is not isolated")
    CONFIG.mkdir(mode=0o750)
    os.chown(CONFIG, 0, account.pw_gid)
    for path in (CONFIG / "provisioning", CONFIG / "provisioning/datasources"):
        path.mkdir(mode=0o750)
        os.chown(path, 0, account.pw_gid)
    password = secrets.token_urlsafe(24)
    write_new(CONFIG / "initial-admin-password", password, gid=account.pw_gid)
    write_new(CONFIG / "secret-key", secrets.token_urlsafe(48), gid=account.pw_gid)
    write_new(CONFIG / "grafana.ini", ini, gid=account.pw_gid)
    datasource = {"apiVersion": 1, "datasources": [{"name": "iCheck Prometheus",
        "uid": "icheck-prometheus", "type": "prometheus", "access": "proxy", "orgId": 1,
        "url": "http://127.0.0.1:9090", "isDefault": True, "editable": False,
        "jsonData": {"httpMethod": "POST", "timeInterval": "30s", "prometheusType": "Prometheus"}}]}
    # JSON is valid YAML; use the .yaml suffix recognized by Grafana's loader.
    write_new(CONFIG / "provisioning/datasources/prometheus.yaml", json.dumps(datasource, indent=2), gid=account.pw_gid)
    os.symlink("grafana-releases/" + VERSION, ACTIVE)
    write_new(UNIT, (Path(__file__).parent / "grafana-server.service").read_bytes(), mode=0o644)
    owner = pwd.getpwnam("zhao")
    private = Path(owner.pw_dir) / ".icheck"
    info = private.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner.pw_uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Existing private operator custody directory is unsafe")
    credential = private / "grafana-login.json"
    write_new(credential, json.dumps({"url": public_url, "username": USERNAME, "password": password,
        "note": "Separate Grafana account; iCheck and Grafana sessions are independent."}, indent=2) + "\n",
        uid=owner.pw_uid, gid=owner.pw_gid, mode=0o600)
    BACKUP.mkdir(mode=0o700)
    write_new(BACKUP / "nginx.conf.before", original, mode=0o600)
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemctl", "enable", "--now", "grafana-server.service"])
    for _ in range(60):
        try:
            if api_call("/api/health", password=password).get("database") == "ok":
                break
        except Exception:
            time.sleep(1)
    else:
        raise RuntimeError("Grafana did not become ready")
    api_call("/apis/folder.grafana.app/v1/namespaces/default/folders", password=password,
             method="POST", data={"metadata": {"name": "icheck"}, "spec": {"title": "iCheck"}})
    saved = []
    for dashboard in baseline_dashboards(icheck_url=public_url.removesuffix("grafana/")):
        result = api_call("/apis/dashboard.grafana.app/v1/namespaces/default/dashboards",
                          password=password, method="POST", data=dashboard)
        uid = result["metadata"]["name"]
        saved.append({"uid": uid, "title": result["spec"]["title"],
                      "url": public_url + "d/" + uid, "resource_version": result["metadata"]["resourceVersion"]})
    temporary = INGRESS.parent / "nginx.grafana-new.conf"
    write_new(temporary, extended, gid=INGRESS.stat().st_gid, mode=stat.S_IMODE(INGRESS.stat().st_mode))
    try:
        run(["/usr/sbin/runuser", "-u", "www-data", "--", "/usr/sbin/nginx", "-t", "-c", str(temporary)])
        os.replace(temporary, INGRESS)
        # The hardened nginx unit has no ExecReload; signal the existing master.
        run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=HUP", "nginx.service"])
    finally:
        temporary.unlink(missing_ok=True)
    record = {"grafana_version": VERSION, "edition": "OSS", "artifact_sha256": ARTIFACT_SHA256,
              "unit": "grafana-server.service", "private_listener": "127.0.0.1:3001",
              "data_directory": "/var/lib/icheck-grafana", "public_url": public_url,
              "datasource_uid": "icheck-prometheus", "prometheus_configuration_changed": False,
              "dashboard_provisioning": "API-created; editable and not file-overwritten",
              "dashboards": saved, "operator_credential_file": str(credential),
              "ingress_backup": str(BACKUP / "nginx.conf.before"), "secrets_in_record": False}
    write_new(BACKUP / "deployment.json", json.dumps(record, indent=2) + "\n", mode=0o600)
    print(json.dumps(record), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--acknowledge-native-install", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.acknowledge_native_install:
        parser.error("Require root deployment access and explicit native-install acknowledgement")
    try:
        install(args.artifact, args.public_url)
    except Exception as error:
        print("Grafana installation stopped (" + type(error).__name__ + "). "
              "Inspect existing paths, service and retained backup before retrying; secret details withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
