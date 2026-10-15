"""Bounded native Prometheus exporter reads, shared by test and scrape paths."""
import hashlib
import json
import math
import re
import time
from typing import Literal
from urllib.parse import urlencode

from prometheus_client.parser import text_string_to_metric_families
from pydantic import BaseModel,ConfigDict,Field,model_validator

from .http_metrics import HTTPMonitorSpec,HTTPMetricError,auth_headers,fetch_http

# This is a supported measurement catalog, not a claim that an endpoint has
# enabled collectors or returned data. Versions/collector results are tested.
CATALOG={
    "linux": {
        "cpu":{"collectors":["cpu"],"metrics":{"node_cpu_seconds_total":"counter"}},
        "memory":{"collectors":["meminfo"],"metrics":{"node_memory_MemAvailable_bytes":"gauge","node_memory_MemTotal_bytes":"gauge"}},
        "disk":{"collectors":["filesystem"],"metrics":{"node_filesystem_avail_bytes":"gauge","node_filesystem_size_bytes":"gauge"}},
        "network":{"collectors":["netdev"],"metrics":{"node_network_receive_bytes_total":"counter","node_network_transmit_bytes_total":"counter"}},
        "uptime":{"collectors":["stat","time"],"metrics":{"node_boot_time_seconds":"gauge","node_time_seconds":"gauge"}},
    },
    "windows": {
        "cpu":{"collectors":["cpu"],"metrics":{"windows_cpu_time_total":"counter"}},
        "memory":{"collectors":["memory"],"metrics":{"windows_memory_available_bytes":"gauge","windows_memory_physical_total_bytes":"gauge"}},
        "disk":{"collectors":["logical_disk"],"metrics":{"windows_logical_disk_free_bytes":"gauge","windows_logical_disk_size_bytes":"gauge"}},
        "network":{"collectors":["net"],"metrics":{"windows_net_bytes_received_total":"counter","windows_net_bytes_sent_total":"counter"}},
        "uptime":{"collectors":["system"],"metrics":{"windows_system_boot_time_timestamp":"gauge"}},
    },
    "containers": {
        "cpu":{"collectors":["cpu"],"metrics":{"container_cpu_usage_seconds_total":"counter"}},
        "memory":{"collectors":["memory"],"metrics":{"container_memory_working_set_bytes":"gauge","container_spec_memory_limit_bytes":"gauge"}},
        "disk":{"collectors":["disk"],"metrics":{"container_fs_usage_bytes":"gauge","container_fs_limit_bytes":"gauge"}},
        "network":{"collectors":["network"],"metrics":{"container_network_receive_bytes_total":"counter","container_network_transmit_bytes_total":"counter"}},
        "uptime":{"collectors":["metadata"],"metrics":{"container_start_time_seconds":"gauge"}},
    },
}
PROTOCOLS={"linux":"node_exporter","windows":"windows_exporter","containers":"cadvisor","vmware":"vmware_exporter"}
SUCCESS={"linux":"node_scrape_collector_success","windows":"windows_exporter_collector_success","containers":"container_scrape_error"}
DEFAULT_PORTS={"linux":9100,"windows":9182,"containers":8080,"vmware":9272}


class ExporterMonitorSpec(BaseModel):
    model_config=ConfigDict(extra="forbid")
    contract:Literal["icheck.exporter-monitor/v1"]="icheck.exporter-monitor/v1"
    plugin:Literal["linux","windows","containers","vmware"]
    groups:list[str]=Field(min_length=1,max_length=5)
    scheme:Literal["http","https"]="https"
    server_name:str|None=None
    auth_mode:Literal["none","basic","bearer"]="none"
    container_id:str|None=Field(default=None,min_length=1,max_length=512)
    container_name:str|None=Field(default=None,min_length=1,max_length=255)
    vmware_scope:Literal["hosts","vms","datastores"]|None=None
    vmware_name:str|None=Field(default=None,min_length=1,max_length=255)
    vmware_datacenter:str|None=Field(default=None,min_length=1,max_length=255)

    @model_validator(mode="after")
    def valid(self):
        if self.plugin=="vmware" and (self.vmware_scope is None or self.vmware_name is None):
            raise ValueError("Choose a VMware object type and exact observed name")
        if self.plugin!="vmware" and any(value is not None for value in (self.vmware_scope,self.vmware_name,self.vmware_datacenter)):
            raise ValueError("VMware selectors belong only to the VMware plugin")
        if any(any(ord(c)<32 or ord(c)==127 for c in value) for value in (self.vmware_name,self.vmware_datacenter) if value):
            raise ValueError("VMware selectors must not contain control characters")
        if len(set(self.groups))!=len(self.groups) or any(g not in self.catalog() for g in self.groups):
            raise ValueError("Choose distinct supported exporter measurement groups")
        if self.scheme=="http" and self.auth_mode!="none":
            raise ValueError("Exporter credentials require verified HTTPS")
        if self.plugin!="containers" and (self.container_id is not None or self.container_name is not None):
            raise ValueError("Container selectors belong only to the container plugin")
        if self.container_id and self.container_name or self.container_id=="/":
            raise ValueError("Choose one exact runtime container selector, never the host root cgroup")
        if any(any(ord(c)<32 or ord(c)==127 for c in value) for value in (self.container_id,self.container_name) if value):
            raise ValueError("Container selectors must not contain control characters")
        self.request()  # Reuse validated SNI and credential-free request rules.
        return self

    def collectors(self):
        return list(dict.fromkeys(c for group in self.groups for c in self.catalog()[group]["collectors"]))

    def catalog(self):
        if self.plugin=="vmware":
            from .vmware_metrics import CATALOG as vmware_catalog
            return vmware_catalog[self.vmware_scope]
        return CATALOG[self.plugin]

    def metrics(self):
        return {name:kind for group in self.groups for name,kind in self.catalog()[group]["metrics"].items()}

    def request(self):
        return HTTPMonitorSpec(mode="probe",scheme=self.scheme,method="GET",auth_mode=self.auth_mode,
            server_name=self.server_name,path="/metrics" if self.plugin in {"containers","vmware"} else "/metrics?"+urlencode([("collect[]",c) for c in self.collectors()]),max_response_bytes=2_000_000)


def document(spec):
    # Keep Linux/Windows v1 hashes and persisted definitions byte-compatible.
    excluded=set()
    if spec.plugin!="containers": excluded.update({"container_id","container_name"})
    if spec.plugin!="vmware": excluded.update({"vmware_scope","vmware_name","vmware_datacenter"})
    return spec.model_dump(exclude=excluded)


def health_metric(spec):
    if spec.plugin=="vmware":
        from .vmware_metrics import HEALTH
        return HEALTH[spec.vmware_scope]
    return SUCCESS[spec.plugin]


def spec_hash(spec):
    return hashlib.sha256(json.dumps(document(spec),sort_keys=True,separators=(",",":")).encode()).hexdigest()


def validate_response(spec,body,*,values=None,headers=None,max_samples=20000):
    if spec.plugin=="vmware":
        from .vmware_metrics import render_vmware_metrics
        return render_vmware_metrics(spec,body,values=values,headers=headers,max_samples=max_samples)[1]
    if spec.plugin=="containers":
        from .container_metrics import render_container_metrics
        return render_container_metrics(spec,body,values=values,headers=headers,max_samples=max_samples)[1]
    if len(body)>2_000_000: raise HTTPMetricError("Exporter response exceeds its byte budget")
    forbidden=[value for value in (values or {}).values() if isinstance(value,str) and value]
    forbidden += [value.split(" ",1)[1] for key,value in (headers or {}).items() if key.lower()=="authorization" and " " in value]
    if any(value.encode() in body for value in forbidden):
        raise HTTPMetricError("Exporter echoed protected credential material")
    try: text=body.decode("utf-8")
    except UnicodeError: raise HTTPMetricError("Exporter response is not UTF-8") from None
    if sum(1 for line in text.splitlines() if line.strip() and not line.startswith("#"))>max_samples:
        raise HTTPMetricError("Exporter response exceeds its sample budget")
    if any(len(line)>65536 for line in text.splitlines()):
        raise HTTPMetricError("Exporter metric line exceeds its bound")
    wanted=spec.metrics(); names=set(); successes={}; count=0; seen=set()
    try:
        for family in text_string_to_metric_families(text):
            for sample in family.samples:
                count+=1
                if count>max_samples: raise HTTPMetricError("Exporter response exceeds its sample budget")
                value=float(sample.value)
                if not math.isfinite(value): raise HTTPMetricError("Exporter returned nonfinite metric samples")
                if sample.timestamp is not None or len(sample.labels)>64 or any(len(k)>128 or len(v)>2048 for k,v in sample.labels.items()):
                    raise HTTPMetricError("Exporter timestamp or labels exceed their bounds")
                if any(k.startswith("icheck_") or k=="__name__" or re.search(r"password|secret|token|community",k,re.I) for k in sample.labels):
                    raise HTTPMetricError("Exporter labels contain reserved or sensitive fields")
                if any(secret in label for label in sample.labels.values() for secret in forbidden):
                    raise HTTPMetricError("Exporter label echoed protected credential material")
                series=(sample.name,tuple(sorted(sample.labels.items())))
                if series in seen: raise HTTPMetricError("Exporter returned duplicate metric series")
                seen.add(series)
                if sample.name in wanted:
                    if (family.type!=wanted[sample.name] or sample.timestamp is not None or
                            (wanted[sample.name]=="counter" and value<0)):
                        raise HTTPMetricError("Exporter metric type, timestamp or counter value is invalid")
                    names.add(sample.name)
                if sample.name==SUCCESS[spec.plugin]:
                    if family.type != "gauge": raise HTTPMetricError("Exporter collector result must be a gauge")
                    collector=sample.labels.get("collector")
                    if collector in spec.collectors():
                        if collector in successes or sample.timestamp is not None: raise HTTPMetricError("Exporter collector evidence is ambiguous")
                        successes[collector]=value
    except (ValueError,TypeError,KeyError,UnicodeError):
        raise HTTPMetricError("Exporter metrics failed bounded validation; inspect collector support and response format") from None
    if names!=set(wanted) or set(successes)!=set(spec.collectors()) or any(value!=1 for value in successes.values()):
        raise HTTPMetricError("Exporter did not provide every requested metric and successful collector result")
    return {"success":True,"spec_hash":spec_hash(spec),"metric_names":sorted(names),"metric_samples":count,
        "collectors":spec.collectors(),"collector_success":True}


def collect(spec,host,port,*,values=None,deadline,tls_context=None):
    request=spec.request(); headers=auth_headers(request,values)
    headers["Accept"]="text/plain; version=0.0.4"
    result=fetch_http(request,host,port,headers,deadline=deadline,tls_context=tls_context)
    if result.status!=200: raise HTTPMetricError("Exporter returned an unsuccessful HTTP status")
    if result.content_type not in {"text/plain","application/openmetrics-text"}:
        raise HTTPMetricError("Exporter response is not Prometheus text")
    body=result.body
    if spec.plugin in {"containers","vmware"}:
        if spec.plugin=="vmware":
            from .vmware_metrics import render_vmware_metrics as render
        else:
            from .container_metrics import render_container_metrics as render
        body,proof=render(spec,body,values=values,headers=headers)
    else:
        proof=validate_response(spec,body,values=values,headers=headers)
    return body,{**proof,"status_code":result.status,"latency_ms":round(result.seconds*1000),
        "tls_tested":spec.scheme=="https","authentication_tested":spec.auth_mode!="none"}
