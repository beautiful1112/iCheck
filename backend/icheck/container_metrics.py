"""cAdvisor measurement projection; never expose environment/arbitrary labels.

Preserve source sample timestamps. A current scrape or container_last_seen value
alone is not proof that cached CPU/memory/network measurements are current.
"""
import json
import math
import time

from prometheus_client.parser import text_string_to_metric_families
from .http_metrics import HTTPMetricError

SAFE_LABELS = {"id", "name", "image", "cpu", "device", "interface"}
HEALTH_NAMES = ["container_scrape_error", "container_last_seen"]
STATIC_NAMES = {"container_spec_memory_limit_bytes", "container_fs_limit_bytes", "container_start_time_seconds"}
MAX_CONTAINERS = 32
MAX_AGE_SECONDS = 60


def render_container_metrics(spec, body, *, values=None, headers=None, max_samples=20000, now=None):
    from .exporter_metrics import spec_hash
    now = time.time() if now is None else now
    secrets = [value for value in (values or {}).values() if isinstance(value, str) and value]
    secrets += [value.split(" ", 1)[1] for key, value in (headers or {}).items() if key.lower() == "authorization" and " " in value]
    if len(body) > 2_000_000 or any(value.encode() in body for value in secrets):
        raise HTTPMetricError("Container response exceeds its bound or echoed protected credential material")
    try:
        text = body.decode("utf-8")
        lines = text.splitlines()
        if any(len(line) > 65536 for line in lines) or sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in lines) > max_samples:
            raise ValueError()
        wanted = spec.metrics()
        samples = []
        container_metrics = {}
        last_seen = {}
        identities = {}
        health = []
        seen = set()
        count = 0
        for family in text_string_to_metric_families(text):
            for sample in family.samples:
                count += 1
                value = float(sample.value)
                if (count > max_samples or not math.isfinite(value) or len(sample.labels) > 64
                        or any(len(key) > 128 or len(label) > 2048 for key, label in sample.labels.items())
                        or any(secret in label for label in sample.labels.values() for secret in secrets)):
                    raise ValueError()
                if sample.name == "container_scrape_error":
                    if family.type != "gauge" or sample.labels or sample.timestamp is not None or value != 0:
                        raise ValueError()
                    health.append(sample)
                    continue
                if sample.name not in wanted and sample.name != "container_last_seen":
                    continue
                identifier = sample.labels.get("id")
                image = sample.labels.get("image")
                name = sample.labels.get("name", "")
                if not identifier or identifier == "/" or not image:
                    continue  # Host/raw cgroups are not a runtime container.
                if len(identifier) > 512 or (spec.container_id and identifier != spec.container_id) or (spec.container_name and name != spec.container_name):
                    continue
                identity = (image, name)
                if identifier in identities and identities[identifier] != identity:
                    raise ValueError()
                identities[identifier] = identity
                if len(identities) > MAX_CONTAINERS:
                    raise ValueError()
                expected = "gauge" if sample.name == "container_last_seen" else wanted[sample.name]
                if family.type != expected or value < 0:
                    raise ValueError()
                timestamp = float(sample.timestamp) if sample.timestamp is not None else None
                if timestamp is not None and (not math.isfinite(timestamp) or not now - MAX_AGE_SECONDS <= timestamp <= now + 5):
                    raise ValueError()
                if sample.name not in STATIC_NAMES and timestamp is None:
                    raise ValueError()  # cAdvisor timestamps its measured statistics.
                labels = {key: label for key, label in sample.labels.items() if key in SAFE_LABELS}
                if any(any(ord(character) < 32 or ord(character) == 127 for character in label) for label in labels.values()):
                    raise ValueError()
                series = (sample.name, tuple(sorted(labels.items())))
                if series in seen:
                    raise ValueError()  # Dropped labels must not merge distinct series.
                seen.add(series)
                if sample.name == "container_last_seen":
                    if not now - MAX_AGE_SECONDS <= value <= now + 5 or identifier in last_seen:
                        raise ValueError()
                    last_seen[identifier] = value
                else:
                    container_metrics.setdefault(identifier, set()).add(sample.name)
                samples.append((sample.name, labels, value, timestamp))
        if (len(health) != 1 or not identities or set(last_seen) != set(identities)
                or set(container_metrics) != set(identities)
                or any(names != set(wanted) for names in container_metrics.values())):
            raise ValueError()
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise HTTPMetricError("Container metric test failed: require fresh declared measurements for every matching runtime container and a successful cAdvisor scrape") from None
    output = ["# TYPE container_scrape_error gauge", "container_scrape_error 0"]
    for name in [*wanted, "container_last_seen"]:
        output.append(f"# TYPE {name} {wanted.get(name, 'gauge')}")
        for metric, labels, value, timestamp in samples:
            if metric != name:
                continue
            label_text = ",".join(key + "=" + json.dumps(label, ensure_ascii=False) for key, label in sorted(labels.items()))
            # Preserve source milliseconds; never turn a cached value into a fresh sample.
            stamp = " " + str(round(timestamp * 1000)) if timestamp is not None else ""
            output.append(f"{name}{{{label_text}}} {value:.17g}{stamp}")
    result = ("\n".join(output) + "\n").encode()
    if len(result) > 2_000_000:
        raise HTTPMetricError("Projected container metrics exceed their byte budget")
    return result, {"success": True, "spec_hash": spec_hash(spec), "metric_names": sorted(wanted),
        "metric_samples": len(samples), "collectors": spec.collectors(), "collector_success": True,
        "container_ids": sorted(identities), "container_count": len(identities), "source_timestamps_preserved": True,
        "labels_filtered": True, "application_health_verified": False}
