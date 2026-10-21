"""Portable read bridge for products without a native adapter.

The bridge exposes this versioned wire contract over one approved HTTPS endpoint.
It translates its vendor's API; it cannot supply code, URLs, credentials or tools.
"""
from datetime import UTC, datetime
import json
from typing import Literal

from pydantic import Field

from .contracts import (ConnectorModel, ReadScope, HistoryQuery, ResourceObservation,
                        AlertObservation, MetricSample, ObservationBatch)
from .zabbix import ConnectorError, MAX_RESPONSE_BYTES, _id, _number, _text, _normalized_read


class BridgeRequest(ConnectorModel):
    protocol: Literal["icheck.monitoring-bridge/v1"] = "icheck.monitoring-bridge/v1"
    operation: Literal["groups", "manifest", "resources", "active", "events", "metrics", "history"]
    scope: ReadScope | None = None
    ids: tuple[str, ...] = Field(default=(), max_length=250)
    after: str = "0"
    since: datetime | None = None
    search: str = Field(default="", max_length=128)
    query: HistoryQuery | None = None


class BridgeConnector:
    def __init__(self, source, transport, *, now=lambda: datetime.now(UTC)):
        if source.provider != "rest_webhook":
            raise ValueError("Bridge adapter requires a bridge source")
        self.source, self.transport, self.now = source, transport, now

    def call(self, operation, **kwargs):
        request = BridgeRequest(operation=operation, **kwargs)
        if operation != "groups" and request.scope is None:
            raise ConnectorError("invalid_source_request")
        try:
            response = self.transport.request(request.model_dump(mode="json"),
                timeout_seconds=request.scope.timeout_seconds if request.scope else 10,
                max_response_bytes=MAX_RESPONSE_BYTES)
        except ConnectorError:
            raise
        except Exception:
            raise ConnectorError("source_unavailable") from None
        if len(json.dumps(response, allow_nan=False).encode()) > MAX_RESPONSE_BYTES:
            raise ConnectorError("source_response_too_large")
        if (not isinstance(response, dict) or set(response) != {"protocol", "operation", "items", "truncated"}
            or response["protocol"] != request.protocol or response["operation"] != operation
            or type(response["truncated"]) is not bool or not isinstance(response["items"], list)):
            raise ConnectorError("invalid_source_response")
        return response

    def batch(self, response, model, limit, scope):
        if len(response["items"]) > limit:
            raise ConnectorError("source_response_too_large")
        # Source references are constructed by iCheck, not accepted from a bridge.
        def ref(kind, identifier):
            return {"source": self.source, "object_type": kind, "remote_id": _id(identifier)}
        def resource(raw):
            data = dict(raw)
            identity = _id(data.pop("id"))
            groups = data.pop("group_ids")
            if (not isinstance(groups, list) or not 1 <= len(groups) <= 100
                or not {_id(v) for v in groups}.intersection(scope.group_ids)
                or type(data.get("monitoring_enabled")) is not bool):
                raise ConnectorError("source_scope_mismatch")
            return ResourceObservation(ref=ref("resource", identity), **data)
        result, seen = [], set()
        for raw in response["items"]:
            data = dict(raw)
            if model is ResourceObservation:
                item = resource(data)
                identity = item.ref.remote_id
            elif model is AlertObservation:
                identity = _id(data.pop("id"))
                subject = _id(data.pop("subject_id"))
                resources = [resource(r) for r in data.pop("resources")]
                if len({r.ref.remote_id for r in resources}) != len(resources):
                    raise ConnectorError("duplicate_source_identity")
                recovery = data.pop("recovery_id")
                if type(data.get("acknowledged")) is not bool or type(data.get("suppressed")) is not bool:
                    raise ConnectorError("invalid_source_response")
                item = model(ref=ref("problem", identity), subject=ref("condition", subject), resources=resources,
                             recovery_ref=ref("event", recovery) if recovery is not None else None, **data)
                _number(item.native_severity, maximum=5)
            else:
                metric, resource = data.pop("metric_id"), data.pop("resource_id")
                item = model(metric=ref("metric", metric), resource=ref("resource", resource), **data)
                identity = (metric, item.timestamp, item.nanoseconds)
            if identity in seen:
                raise ConnectorError("duplicate_source_identity")
            seen.add(identity)
            result.append(item)
        return ObservationBatch(source=self.source, fetched_at=self.now(), items=tuple(result),
                                truncated=response["truncated"])

    @_normalized_read
    def discover_groups(self, search=""):
        response = self.call("groups", search=search)
        if len(response["items"]) > 200:
            raise ConnectorError("source_scope_too_large")
        items = [{"id": _id(r["id"]), "name": _text(r["name"], 255)} for r in response["items"]]
        if len({r["id"] for r in items}) != len(items):
            raise ConnectorError("duplicate_source_identity")
        return {"items": items, "truncated": response["truncated"]}

    def manifest(self, operation, scope):
        response = self.call(operation, scope=scope)
        if response["truncated"] or len(response["items"]) > 10000:
            raise ConnectorError("source_scope_too_large")
        ids = [_id(value) for value in response["items"]]
        if len(set(ids)) != len(ids):
            raise ConnectorError("duplicate_source_identity")
        return sorted(ids, key=int)

    @_normalized_read
    def resource_manifest(self, scope):
        return self.manifest("manifest", scope)

    @_normalized_read
    def active_event_manifest(self, scope):
        return self.manifest("active", scope)

    @_normalized_read
    def discover_resources(self, scope):
        return self.batch(self.call("resources", scope=scope), ResourceObservation, scope.limit, scope)

    @_normalized_read
    def read_resource_batch(self, scope, host_ids):
        if not host_ids or len(host_ids) > 250 or len(set(host_ids)) != len(host_ids):
            raise ConnectorError("invalid_source_request")
        result = self.batch(self.call("resources", scope=scope, ids=tuple(host_ids)), ResourceObservation, len(host_ids), scope)
        if result.truncated or any(r.ref.remote_id not in host_ids for r in result.items):
            raise ConnectorError("source_scope_mismatch")
        return result

    @_normalized_read
    def read_events(self, scope, *, event_ids=None, after="0", since=None):
        if event_ids is not None:
            if not event_ids or len(event_ids) > 100 or len(set(event_ids)) != len(event_ids):
                raise ConnectorError("invalid_source_request")
        elif since is None or since.tzinfo is None:
            raise ConnectorError("invalid_source_request")
        result = self.batch(self.call("events", scope=scope, ids=tuple(event_ids or ()), after=after, since=since),
                            AlertObservation, 100, scope)
        for item in result.items:
            if ((event_ids is not None and item.ref.remote_id not in event_ids)
                or (event_ids is None and (int(item.ref.remote_id) <= _number(after) or item.occurred_at < since))):
                raise ConnectorError("source_scope_mismatch")
        if event_ids is not None and result.truncated:
            raise ConnectorError("invalid_source_response")
        return result

    def read_alerts(self, scope):
        ids = self.active_event_manifest(scope)
        result = self.read_events(scope, event_ids=ids[:100]) if ids else ObservationBatch(
            source=self.source, fetched_at=self.now(), items=(), truncated=False)
        return result.model_copy(update={"truncated": result.truncated or len(ids) > 100})

    @_normalized_read
    def list_metrics(self, scope, host_id):
        if len(self.read_resource_batch(scope, [_id(host_id)]).items) != 1:
            raise ConnectorError("resource_unavailable_in_scope")
        response = self.call("metrics", scope=scope, ids=(host_id,))
        if len(response["items"]) > 50:
            raise ConnectorError("source_scope_too_large")
        seen, items = set(), []
        for row in response["items"]:
            identity = _id(row["metric_id"])
            if identity in seen or row["value_type"] not in {"float", "uint"}:
                raise ConnectorError("invalid_source_response")
            seen.add(identity)
            items.append({"metric_id": identity, "name": _text(row["name"], 255), "value_type": row["value_type"],
                          "unit": _text(row["unit"], 255) if row["unit"] else None})
        return {"items": items, "truncated": response["truncated"]}

    @_normalized_read
    def query_history(self, scope, query):
        if len(self.read_resource_batch(scope, [_id(query.resource_id)]).items) != 1:
            raise ConnectorError("resource_unavailable_in_scope")
        result = self.batch(self.call("history", scope=scope, query=query), MetricSample, query.limit, scope)
        for sample in result.items:
            if (sample.resource.remote_id != query.resource_id or sample.metric.remote_id != query.metric_id
                or not query.start <= sample.timestamp <= query.end
                or (query.value_type == "uint" and (type(sample.value) is not int or not 0 <= sample.value <= 2**64 - 1))):
                raise ConnectorError("metric_scope_or_type_mismatch")
        return result
