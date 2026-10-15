"""Bounded local module installer channel; no browser/service token forwarding."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct

from .managed_snmp import trusted_file
from .snmp_generator import load_yaml, validate_compiled
from .snmp_module_install import CATALOG

SOCKET = Path("/run/icheck-snmp-installer/install.sock")
MAX_MESSAGE = 4_000_000


def inspect_catalog(compiled):
    module = validate_compiled(compiled)
    try: source = trusted_file(CATALOG)
    except (OSError,ValueError): raise ValueError("Protected SNMP module catalog is unavailable") from None
    if source.stat().st_size > 20_000_000: raise ValueError("SNMP catalog exceeds its byte limit")
    encoded = source.read_bytes(); doc = load_yaml(encoded,maximum=20_000_000)
    if not isinstance(doc,dict) or set(doc) != {"modules"} or not isinstance(doc["modules"],dict):
        raise ValueError("SNMP catalog must contain modules only")
    return {"catalog_sha256":hashlib.sha256(encoded).hexdigest(),
        "installed":doc["modules"].get(compiled["module_name"]) == module}


def receive(connection, length):
    result = bytearray()
    while len(result) < length:
        block = connection.recv(min(65536,length-len(result)))
        if not block: raise ValueError("SNMP installation channel closed before its result")
        result.extend(block)
    return bytes(result)


def send_document(connection, document):
    encoded = json.dumps(document, separators=(",",":"),allow_nan=False).encode()
    if not 0 < len(encoded) <= MAX_MESSAGE: raise ValueError("SNMP installation message exceeds its bound")
    connection.sendall(struct.pack("!I",len(encoded))+encoded)


def receive_document(connection):
    length = struct.unpack("!I",receive(connection,4))[0]
    if not 0 < length <= MAX_MESSAGE: raise ValueError("SNMP installation message exceeds its bound")
    return json.loads(receive(connection,length))


def install_module(compiled, expected_catalog_sha256):
    validate_compiled(compiled)
    try:
        for path in (SOCKET.parent,*SOCKET.parent.parents):
            info=path.lstat()
            if path.is_symlink() or info.st_uid!=0 or info.st_mode & 0o022:
                raise ValueError("SNMP installation socket ancestry is unsafe")
        info=SOCKET.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o660:
            raise ValueError("SNMP installation socket custody is unsafe")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.settimeout(20); channel.connect(str(SOCKET))
            _,uid,_=struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=0: raise ValueError("SNMP installer peer is not the protected root service")
            send_document(channel,{"format":"icheck.snmp-install-request/v1","candidate":compiled,
                "expected_catalog_sha256":expected_catalog_sha256})
            result=receive_document(channel)
    except (OSError,ValueError,TypeError,KeyError,RecursionError):
        # Lost replies do not prove failure: inspect the exact module before a
        # retry. The append-only/CAS store makes an already completed install
        # identifiable without replaying a root write.
        try: current=inspect_catalog(compiled)
        except (OSError,ValueError): current={"installed":False}
        if current["installed"]: return {**current,"module_name":compiled["module_name"],"changed":False}
        raise ValueError("SNMP installation is unavailable or uncertain; inspect module status before retrying") from None
    if (not isinstance(result,dict) or result.get("installed") is not True or result.get("module_name")!=compiled["module_name"]):
        raise ValueError("SNMP module install failed; refresh the catalog preview before retrying")
    return result
