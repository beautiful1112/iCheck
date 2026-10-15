"""One managed rule file and native loopback Prometheus lifecycle API.

Root-provisioned settings select the namespace, backend and directory. Neither
the model nor a rule request chooses a path, endpoint or notification secret.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler, Request
from urllib.error import HTTPError, URLError

import promql_parser
from .config import get_settings

GROUP="icheck.metric-rules"
MAX_BYTES=256000


def canonical(document):
    return json.dumps(document,sort_keys=True,separators=(",",":"),allow_nan=False)


def digest(document):
    return hashlib.sha256(canonical(document).encode()).hexdigest()


def catalog(rules=()):
    return {"groups":[{"name":GROUP,"interval":"15s","rules":sorted(rules,key=lambda row:row["alert"])}]}


class RuleRuntimeError(ValueError): pass
class RuleRuntimeConflict(RuleRuntimeError): pass
class RuleRuntimeUnknown(RuleRuntimeError): pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None


class NativeRuleRuntime:
    def __init__(self):
        settings=get_settings()
        if not all((settings.metric_rule_directory,settings.metric_rule_backend_id,settings.metric_rule_tenant_id,settings.metric_rule_region_id)):
            raise RuleRuntimeError("Native metric-rule runtime is not provisioned; no rule was installed")
        parsed=urlsplit(settings.metric_rule_prometheus_url)
        try: loopback=ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError: loopback=False
        if (parsed.scheme!="http" or not loopback or parsed.username or parsed.password or parsed.path not in {"","/"}
                or parsed.query or parsed.fragment): raise RuleRuntimeError("Rule lifecycle API must be literal loopback HTTP")
        self.directory=Path(settings.metric_rule_directory)
        if not self.directory.is_absolute(): raise RuleRuntimeError("Rule directory must be a protected absolute path")
        self.base=settings.metric_rule_prometheus_url.rstrip("/")
        self.promtool=settings.metric_rule_promtool_path
        if not Path(self.promtool).is_absolute(): raise RuleRuntimeError("Use the provisioned absolute promtool path")
        self.binding={"directory":str(self.directory),"prometheus_url":self.base,"promtool":self.promtool,
            "backend_id":settings.metric_rule_backend_id,"tenant_id":settings.metric_rule_tenant_id,"region_id":settings.metric_rule_region_id,
            "receiver":settings.metric_alert_receiver}
        self.opener=build_opener(ProxyHandler({}),NoRedirect())

    def guard(self,principal,backend_id):
        if (principal.tenant_id!=self.binding["tenant_id"] or principal.region_id!=self.binding["region_id"]
                or backend_id!=self.binding["backend_id"]): raise RuleRuntimeError("Native rule runtime belongs to a different namespace or Prometheus backend")

    def _directory(self):
        try:
            descriptor=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            info=os.fstat(descriptor)
            if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o027:
                os.close(descriptor); raise RuleRuntimeError("Rule directory owner or permissions are unsafe")
            return descriptor
        except OSError: raise RuleRuntimeError("Provisioned metric-rule directory is unavailable") from None

    @contextmanager
    def lock(self):
        directory=self._directory(); descriptor=None
        try:
            descriptor=os.open(".lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=directory)
            info=os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise RuleRuntimeError("Rule runtime lock is unsafe")
            try: fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise RuleRuntimeConflict("Another native rule change is running; inspect it before retrying") from None
            yield
        finally:
            if descriptor is not None: os.close(descriptor)
            os.close(directory)

    def read(self):
        directory=self._directory()
        try:
            try: descriptor=os.open("rules.yml",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            except FileNotFoundError: return catalog()
            with os.fdopen(descriptor,"rb") as handle:
                info=os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)&0o027:
                    raise RuleRuntimeError("Managed rule file owner or permissions are unsafe")
                content=handle.read(MAX_BYTES+1)
            if len(content)>MAX_BYTES: raise RuleRuntimeError("Managed rule catalog exceeds its bound")
            document=json.loads(content)
            group=document["groups"][0]
            if (set(document)!={"groups"} or len(document["groups"])!=1 or group["name"]!=GROUP
                    or group["interval"]!="15s" or len(group["rules"])>100): raise ValueError()
            return document
        except (OSError,ValueError,KeyError,TypeError,IndexError):
            raise RuleRuntimeError("Managed rule catalog cannot be read safely; no write was admitted") from None
        finally: os.close(directory)

    def api(self,path,method="GET"):
        try:
            with self.opener.open(Request(self.base+path,method=method),timeout=3) as response:
                body=response.read(1_000_001)
                if len(body)>1_000_000 or response.status!=200: raise ValueError()
                return json.loads(body) if method=="GET" else None
        except (HTTPError,URLError,OSError,ValueError):
            raise RuleRuntimeUnknown("Prometheus rule reload/inspection outcome is unavailable; inspect the retained change before retrying") from None

    def matches(self,document):
        data=self.api("/api/v1/rules?type=alert")
        if data.get("status")!="success": raise RuleRuntimeUnknown("Prometheus rule inspection failed")
        expected={rule["alert"]:rule for rule in document["groups"][0]["rules"]}
        actual={}
        for group in data.get("data",{}).get("groups",[]):
            if group.get("name")!=GROUP: continue
            for rule in group.get("rules",[]):
                name=rule.get("name")
                if name in actual: return False
                actual[name]=rule
        if set(actual)!=set(expected): return False
        for name,rule in expected.items():
            item=actual[name]
            try:
                if (promql_parser.parse(item["query"]).prettify()!=promql_parser.parse(rule["expr"]).prettify()
                        or item.get("labels")!=rule["labels"] or item.get("annotations")!=rule["annotations"]
                        or item.get("duration")!=int(rule["for"][:-1]) or item.get("health") not in {"ok","unknown"}): return False
            except (ValueError,TypeError,KeyError): return False
        return True

    def write(self,document,expected_hash,*,admit=lambda:None):
        body=(canonical(document)+"\n").encode()
        if len(body)>MAX_BYTES: raise RuleRuntimeError("Rule catalog exceeds its byte bound")
        if digest(self.read())!=expected_hash: raise RuleRuntimeConflict("Native rule catalog changed after preview")
        directory=self._directory(); name=".stage-"+secrets.token_hex(12)+".yml"
        try:
            descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640,dir_fd=directory)
            os.fchmod(descriptor,0o640)
            with os.fdopen(descriptor,"wb") as handle:
                handle.write(body); handle.flush(); os.fsync(handle.fileno())
            try:
                result=subprocess.run([self.promtool,"check","rules",str(self.directory/name)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=False)
            except (OSError,subprocess.TimeoutExpired): raise RuleRuntimeError("Native promtool validation is unavailable") from None
            if result.returncode!=0: raise RuleRuntimeError("Native promtool rejected the reviewed rules")
            if digest(self.read())!=expected_hash: raise RuleRuntimeConflict("Native rule catalog changed during validation")
            admit()
            os.replace(name,"rules.yml",src_dir_fd=directory,dst_dir_fd=directory); os.fsync(directory)
        finally:
            try: os.unlink(name,dir_fd=directory)
            except FileNotFoundError: pass
            os.close(directory)

    def reload(self): self.api("/-/reload",method="POST")
