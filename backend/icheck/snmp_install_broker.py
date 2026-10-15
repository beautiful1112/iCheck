"""One fixed root-owned module catalog; requests only from the local API UID."""
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import struct
import sys

from .managed_snmp import trusted_file
from .snmp_install_client import SOCKET,send_document,receive_document
from .snmp_module_install import CATALOG,EXPORTER,install_module


def handle(channel, *, api_uid, catalog=CATALOG, exporter=EXPORTER):
    channel.settimeout(20)
    try:
        _,uid,_=struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=api_uid: raise ValueError("Caller is not the protected API service")
        request=receive_document(channel)
        if (not isinstance(request,dict) or set(request)!={"format","candidate","expected_catalog_sha256"}
                or request["format"]!="icheck.snmp-install-request/v1"):
            raise ValueError("Invalid SNMP module installation request")
        result=install_module(request["candidate"],catalog=catalog,exporter=exporter,
            expected_catalog_sha256=request["expected_catalog_sha256"],confirm=True)
        send_document(channel,result)
    except (OSError,ValueError,TypeError,KeyError,RecursionError):
        try: send_document(channel,{"installed":False,"error":"Protected module installation failed; refresh its preview"})
        except (OSError,ValueError): pass


def validate_module_custody():
    # The supported /opt/icheck/.venv entry point is a protected release symlink.
    # Validate the canonical installed module and prefix, not that logical alias.
    module = Path(__file__).resolve(strict=True)
    prefix = Path(sys.prefix).resolve(strict=True)
    if not module.is_relative_to(prefix):
        raise ValueError("Installer module is outside its installed interpreter")
    trusted_file(module)


def main():
    # Use the installed interpreter with -I; this service is never run as root
    # from a writable checkout. The peer UID is fixed, not browser-supplied.
    if os.geteuid()!=0: raise RuntimeError("Protected SNMP installer requires root")
    if not sys.flags.isolated: raise RuntimeError("Protected SNMP installer requires isolated Python")
    validate_module_custody(); trusted_file(CATALOG); trusted_file(EXPORTER,executable=True)
    api_uid=pwd.getpwnam("icheck").pw_uid
    if api_uid==0: raise RuntimeError("API service must not run as root")
    for path in (SOCKET.parent,*SOCKET.parent.parents):
        info=path.lstat()
        if path.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:
            raise RuntimeError("Unsafe installer runtime directory")
    if SOCKET.exists():
        # Refuse to take over another service or blindly remove a stale socket.
        raise RuntimeError("Installer socket already exists; inspect the owning process before restart")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(SOCKET)); os.chmod(SOCKET,0o660); server.listen(4)
        try:
            while True:
                channel,_=server.accept()
                with channel: handle(channel,api_uid=api_uid)
        finally:
            SOCKET.unlink(missing_ok=True)


if __name__=="__main__": main()
