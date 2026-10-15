"""Create a single-node evaluation CA and native HTTPS/mTLS config.

No services are started, accounts changed or global trust stores modified.
Existing custody is never replaced. Certificates expire in 90 days. This is
not an enterprise PKI or automatic certificate-rotation implementation.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PKI = Path("/var/lib/icheck-preview-pki")
INGRESS = Path("/etc/icheck-preview-ingress")
WORKERS = Path("/etc/icheck-workers")
HOSTS = ("127.0.0.1",)


def listen_hosts(addresses: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if len(addresses) > 9:
        raise ValueError("Too many preview HTTPS addresses")
    result = list(HOSTS)
    for value in addresses:
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or address.is_reserved:
            raise ValueError("Preview HTTPS requires explicit unicast IPv4 addresses")
        if str(address) not in result:
            result.append(str(address))
    if len(result) > 9:
        raise ValueError("Too many preview HTTPS addresses")
    return tuple(result)


def existing_server_hosts(path: Path, requested: list[str] | None) -> tuple[str, ...]:
    trusted(path)
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    covered = tuple(str(address) for address in names.get_values_for_type(x509.IPAddress))
    hosts = listen_hosts(covered if requested is None else requested)
    if not set(hosts).issubset(covered):
        raise ValueError("Configuration refresh cannot add addresses outside the existing server certificate")
    return hosts


def trusted(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe deployment path")


def write_new(path: Path, data: bytes, *, uid: int = 0, gid: int = 0, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchown(handle.fileno(), uid, gid)
        os.fchmod(handle.fileno(), mode)


def issue(name: str, *, issuer_cert=None, issuer_key=None, server: bool = False,
          hosts: tuple[str, ...] | None = None):
    server_hosts = listen_hosts(HOSTS if hosts is None else hosts)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    ca = issuer_cert is None
    builder = (x509.CertificateBuilder().subject_name(subject)
        .issuer_name(subject if ca else issuer_cert.subject).public_key(key.public_key())
        .serial_number(secrets.randbits(152) | (1 << 152))
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 if ca else 90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=not ca, data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(host)) for host in server_hosts] + [x509.DNSName("localhost")]), critical=False)
    certificate = builder.sign(private_key=key if ca else issuer_key, algorithm=hashes.SHA256())
    return key, certificate


def pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def identity_maps(certificates: list) -> str:
    fields = {"sha256": lambda cert: cert.fingerprint(hashes.SHA256()).hex(),
        "subject": lambda cert: cert.subject.rfc4514_string(),
        "serial": lambda cert: str(cert.serial_number),
        "not_after": lambda cert: cert.not_valid_after_utc.isoformat()}
    output = []
    for field, value in fields.items():
        output.append(f'map $ssl_client_serial $icheck_cert_{field} {{\n    default "";')
        for cert in certificates:
            # Fixed issuer custody + unique serials identify ONLY these issued
            # certificates; client-controlled headers never supply metadata.
            output.append(f'    ~*^0*{cert.serial_number:x}$ "{value(cert)}";')
        output.append("}")
    return "\n".join(output)


def configuration(certificates: list, *, hosts: tuple[str, ...] | None = None) -> bytes:
    hosts = listen_hosts(HOSTS if hosts is None else hosts)
    identity = "\n".join(f'proxy_set_header X-iCheck-Client-Cert-{name} "";' for name in ("Verified", "SHA256", "Subject", "Serial", "Not-After"))
    federation = "\n".join(f'proxy_set_header X-Icheck-Trusted-Proxy-{name} "";' for name in ("Verified", "Subject", "Secret"))
    public_listeners = "\n".join(f"listen {host}:8443 ssl;" for host in hosts)
    allowed_host_entries = "\n".join(f"{host} 1;" for host in (*hosts, "localhost"))
    server_names = " ".join((*hosts, "localhost"))
    # Root-run nginx config checks also initialize/chown temporary directories.
    # Pin the same account as the native unit, rather than nginx's default nobody.
    return f"""user www-data www-data;
worker_processes 2;
pid /var/lib/icheck-preview-ingress/nginx.pid;
error_log stderr crit;
events {{ worker_connections 1024; }}
http {{
    default_type application/octet-stream;
    access_log off;
    server_tokens off;
    client_body_temp_path /var/lib/icheck-preview-ingress/client-temp;
    proxy_temp_path /var/lib/icheck-preview-ingress/proxy-temp;
    fastcgi_temp_path /var/lib/icheck-preview-ingress/fastcgi-temp;
    uwsgi_temp_path /var/lib/icheck-preview-ingress/uwsgi-temp;
    scgi_temp_path /var/lib/icheck-preview-ingress/scgi-temp;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/icheck-preview-ingress/server.pem;
    ssl_certificate_key /etc/icheck-preview-ingress/server.key;
    {identity_maps(certificates)}
    map $host $icheck_public_host_allowed {{
        default 0;
        {allowed_host_entries}
    }}
    server {{
        {public_listeners}
        server_name {server_names};
        if ($icheck_public_host_allowed = 0) {{ return 421; }}
        client_max_body_size 10m;
        location = /preview-ca.crt {{ alias /etc/icheck-preview-ingress/preview-ca.pem; }}
        location = /api/v1/auth/bootstrap {{ return 404; }}
        location /api/v1/ {{
            proxy_pass http://127.0.0.1:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host:$server_port;
            proxy_set_header Connection "";
            proxy_set_header X-Icheck-Bootstrap-Token "";
            {identity}
            {federation}
            proxy_buffering off;
            proxy_read_timeout 300s;
        }}
        location / {{
            proxy_pass http://127.0.0.1:3000;
            proxy_http_version 1.1;
            proxy_set_header Host $host:$server_port;
            proxy_set_header Connection "";
            {identity}
            {federation}
        }}
    }}
    server {{
        listen 127.0.0.1:8444 ssl;
        server_name localhost 127.0.0.1;
        ssl_client_certificate /etc/icheck-preview-ingress/preview-ca.pem;
        ssl_verify_client on;
        ssl_verify_depth 1;
        if ($icheck_cert_sha256 = "") {{ return 403; }}
        client_max_body_size 20m;
        location /api/v1/ {{
            proxy_pass http://127.0.0.1:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host:$server_port;
            proxy_set_header Connection "";
            proxy_set_header X-iCheck-Client-Cert-Verified $ssl_client_verify;
            proxy_set_header X-iCheck-Client-Cert-SHA256 $icheck_cert_sha256;
            proxy_set_header X-iCheck-Client-Cert-Subject $icheck_cert_subject;
            proxy_set_header X-iCheck-Client-Cert-Serial $icheck_cert_serial;
            proxy_set_header X-iCheck-Client-Cert-Not-After $icheck_cert_not_after;
            {federation}
            proxy_buffering off;
            proxy_read_timeout 300s;
        }}
        location / {{ return 404; }}
    }}
}}
""".encode()


def prepare(addresses: list[str] | None = None) -> dict:
    hosts = listen_hosts(addresses or [])
    for parent in (PKI.parent, INGRESS.parent, WORKERS):
        trusted(parent)
    paths = (PKI, INGRESS, WORKERS / "collector", WORKERS / "agent")
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError("Existing PKI or worker custody; inspect rather than replace")
    ingress_user = pwd.getpwnam("www-data")
    accounts = {name: pwd.getpwnam(account) for name, account in (("collector", "icheck-collector"), ("agent", "icheck-agent"))}
    PKI.mkdir(mode=0o700)
    INGRESS.mkdir(mode=0o750)
    os.chown(INGRESS, 0, ingress_user.pw_gid)
    issuer_key, issuer = issue("iCheck v0.1 evaluation CA")
    ca_pem = issuer.public_bytes(serialization.Encoding.PEM)
    write_new(PKI / "issuer.key", pem_key(issuer_key))
    write_new(PKI / "preview-ca.pem", ca_pem, mode=0o644)
    write_new(INGRESS / "preview-ca.pem", ca_pem, gid=ingress_user.pw_gid, mode=0o644)
    server_key, server = issue("iCheck v0.1 evaluation HTTPS", issuer_cert=issuer, issuer_key=issuer_key, server=True, hosts=hosts)
    write_new(INGRESS / "server.key", pem_key(server_key), uid=ingress_user.pw_uid, gid=ingress_user.pw_gid)
    write_new(INGRESS / "server.pem", server.public_bytes(serialization.Encoding.PEM), mode=0o644)
    clients = []
    for name, account in accounts.items():
        directory = WORKERS / name
        directory.mkdir(mode=0o750)
        os.chown(directory, 0, account.pw_gid)
        key, certificate = issue("icheck-preview-" + name, issuer_cert=issuer, issuer_key=issuer_key)
        write_new(directory / "worker-ca.pem", ca_pem, mode=0o644)
        write_new(directory / "client.pem", certificate.public_bytes(serialization.Encoding.PEM), mode=0o644)
        write_new(directory / "client.key", pem_key(key), uid=account.pw_uid, gid=account.pw_gid)
        clients.append(certificate)
    write_new(INGRESS / "nginx.conf", configuration(clients, hosts=hosts), gid=ingress_user.pw_gid, mode=0o640)
    return {"prepared": True, "ca_sha256": issuer.fingerprint(hashes.SHA256()).hex(),
        "server_expires_at": server.not_valid_after_utc.isoformat(),
        "worker_certificates": len(clients), "public_https_port": 8443, "https_addresses": list(hosts),
        "worker_https_listener": "127.0.0.1:8444", "services_started": False, "global_ca_trust_changed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-lab-only-pki", action="store_true")
    parser.add_argument("--listen-ip", action="append", help="Explicit server IPv4 address; repeat for multiple interfaces. New installs default to loopback only")
    parser.add_argument("--refresh-config", action="store_true", help="Re-render only ingress configuration from the existing two issued client certificates; never replace keys or CA")
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.acknowledge_lab_only_pki:
        parser.error("Requires the root deployment operator and explicit evaluation-PKI acknowledgement")
    try:
        trusted(Path(__file__).absolute())
        if args.refresh_config:
            trusted(INGRESS / "nginx.conf")
            hosts = existing_server_hosts(INGRESS / "server.pem", args.listen_ip)
            certificates = []
            for name in ("collector", "agent"):
                path = WORKERS / name / "client.pem"
                trusted(path)
                certificates.append(x509.load_pem_x509_certificate(path.read_bytes()))
            temporary = INGRESS / (".nginx-" + secrets.token_hex(12))
            write_new(temporary, configuration(certificates, hosts=hosts), gid=pwd.getpwnam("www-data").pw_gid, mode=0o640)
            os.replace(temporary, INGRESS / "nginx.conf")
            result = {"configuration_refreshed": True, "https_addresses": list(hosts), "keys_replaced": False, "services_started": False}
        else:
            result = prepare(args.listen_ip)
    except Exception as error:
        print(json.dumps({"passed": False, "error_type": type(error).__name__, "inspect_before_retrying": True}))
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
