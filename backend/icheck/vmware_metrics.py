"""Selected-object projection for the vmware_exporter 0.18.x wire contract.

The upstream queries vSphere on each /metrics request but omits source timestamps.
Scrape freshness is not proof of the original performance-sample age or health.
"""
import json
import math
import time

from prometheus_client.parser import text_string_to_metric_families
from .http_metrics import HTTPMetricError


def group(scope, *names):
    return {"collectors": [scope], "metrics": {name: "gauge" for name in names}}


CATALOG = {
    "hosts": {
        "cpu": group("hosts", "vmware_host_cpu_usage", "vmware_host_cpu_max"),
        "memory": group("hosts", "vmware_host_memory_usage", "vmware_host_memory_max"),
        "disk": group("hosts", "vmware_host_disk_read_average", "vmware_host_disk_write_average"),
        "network": group("hosts", "vmware_host_net_bytesRx_average", "vmware_host_net_bytesTx_average"),
        "uptime": group("hosts", "vmware_host_boot_timestamp_seconds"),
    },
    "vms": {
        "cpu": group("vms", "vmware_vm_cpu_usagemhz_average", "vmware_vm_max_cpu_usage"),
        "memory": group("vms", "vmware_vm_mem_usage_average", "vmware_vm_memory_max"),
        "disk": group("vms", "vmware_vm_guest_disk_capacity", "vmware_vm_guest_disk_free"),
        "network": group("vms", "vmware_vm_net_received_average", "vmware_vm_net_transmitted_average"),
        "uptime": group("vms", "vmware_vm_boot_timestamp_seconds"),
    },
    "datastores": {
        "disk": group("datastores", "vmware_datastore_capacity_size", "vmware_datastore_freespace_size"),
    },
}
LABEL = {"hosts": "host_name", "vms": "vm_name", "datastores": "ds_name"}
HEALTH = {"hosts": "vmware_host_power_state", "vms": "vmware_vm_power_state", "datastores": "vmware_datastore_accessible"}
SAFE_LABELS = {"host_name", "vm_name", "ds_name", "dc_name", "cluster_name", "ds_cluster", "partition"}


def render_vmware_metrics(spec, body, *, values=None, headers=None, max_samples=20000):
    from .exporter_metrics import spec_hash
    forbidden = [value for value in (values or {}).values() if isinstance(value, str) and value]
    forbidden += [value.split(" ", 1)[1] for key, value in (headers or {}).items()
        if key.lower() == "authorization" and " " in value]
    if len(body) > 2_000_000 or any(secret.encode() in body for secret in forbidden):
        raise HTTPMetricError("VMware response exceeds its byte bound or echoed protected credential material")
    wanted = spec.metrics(); health = HEALTH[spec.vmware_scope]; label = LABEL[spec.vmware_scope]
    samples = []; seen = set(); identities = set(); names = set(); count = 0
    try:
        text = body.decode("utf-8"); lines = text.splitlines()
        if any(len(line) > 65536 for line in lines) or sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in lines) > max_samples:
            raise ValueError()
        for family in text_string_to_metric_families(text):
            for sample in family.samples:
                count += 1; value = float(sample.value)
                if (count > max_samples or not math.isfinite(value) or len(sample.labels) > 64
                        or any(len(key) > 128 or len(item) > 2048 for key, item in sample.labels.items())
                        or any(secret in item for item in sample.labels.values() for secret in forbidden)):
                    raise ValueError()
                if sample.name not in wanted and sample.name != health: continue
                if sample.labels.get(label) != spec.vmware_name: continue
                if spec.vmware_datacenter is not None and sample.labels.get("dc_name") != spec.vmware_datacenter: continue
                # A name repeated in different datacenters is not one selected object.
                labels = {key: item for key, item in sample.labels.items() if key in SAFE_LABELS}
                datacenter = labels.get("dc_name")
                if not datacenter or len(datacenter)>255: raise ValueError()
                identities.add(tuple(sorted((key,item) for key,item in labels.items() if key!="partition")))
                if len(identities) != 1 or family.type != "gauge" or sample.timestamp is not None or value < 0:
                    raise ValueError()
                if sample.name == health and value not in {0, 1}: raise ValueError()
                if sample.name.endswith("boot_timestamp_seconds") and not 0<value<=time.time()+5: raise ValueError()
                if sample.name=="vmware_vm_mem_usage_average" and value>10000: raise ValueError()
                if any(any(ord(c) < 32 or ord(c) == 127 for c in item) for item in labels.values()): raise ValueError()
                series = (sample.name, tuple(sorted(labels.items())))
                if series in seen: raise ValueError()
                seen.add(series); names.add(sample.name); samples.append((sample.name, labels, value))
        if names != set(wanted) | {health}: raise ValueError()
        if sum(name == health for name, _, _ in samples) != 1: raise ValueError()
        # Compare multi-series partition coverage, not just global metric names.
        if spec.vmware_scope == "vms" and "disk" in spec.groups:
            partitions = {name: {labels.get("partition") for metric, labels, _ in samples if metric == name}
                for name in ("vmware_vm_guest_disk_capacity", "vmware_vm_guest_disk_free")}
            capacity, free = partitions.values()
            if not capacity or len(capacity)>128 or None in capacity or "" in capacity or capacity != free: raise ValueError()
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise HTTPMetricError("VMware metric test failed: require every declared measurement and object state for one unambiguous selected object") from None
    output = []
    for name in [*wanted, health]:
        output.append(f"# TYPE {name} gauge")
        for metric, labels, value in samples:
            if metric == name:
                fields = ",".join(key + "=" + json.dumps(item, ensure_ascii=False) for key, item in sorted(labels.items()))
                output.append(f"{name}{{{fields}}} {value:.17g}")
    result = ("\n".join(output) + "\n").encode()
    if len(result) > 2_000_000: raise HTTPMetricError("Projected VMware metrics exceed their byte bound")
    return result, {"success": True, "spec_hash": spec_hash(spec), "metric_names": sorted(wanted),
        "metric_samples": len(samples), "collectors": spec.collectors(), "collector_success": True,
        "vmware_scope": spec.vmware_scope, "vmware_name": spec.vmware_name,
        "vmware_datacenter": dict(next(iter(identities)))["dc_name"], "labels_filtered": True,
        "source_timestamp_available": False, "sample_freshness_scope": "gateway_receipt", "object_health_verified": False}
