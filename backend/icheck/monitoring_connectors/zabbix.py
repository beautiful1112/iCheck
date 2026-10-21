"""Zabbix 7.0/7.4 read adapter with no ambient network or credential access.

The connection service supplies a namespace-authorized, endpoint-bound
transport. That transport must enforce TLS, egress, credential custody, timeout
and byte limits before JSON decoding. This module neither builds arbitrary URLs
nor accepts arbitrary API methods. No transport is installed by default.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from typing import Any, Protocol
from uuid import uuid4

from .contracts import (
    AlertObservation, HistoryQuery, MetricSample, ObservationBatch,
    ReadScope, RemoteRef, ResourceObservation, SourceIdentity,
)


MAX_RESPONSE_BYTES = 2_000_000
_READ_METHODS = frozenset({"apiinfo.version", "host.get", "hostgroup.get", "problem.get", "event.get", "item.get", "history.get"})
_VERSION = re.compile(r"7\.(?:0|4)\.[0-9]+")
_NUMBER = re.compile(r"0|[1-9][0-9]{0,19}")


class ConnectorError(RuntimeError):
    """Stable public diagnostics; do not expose vendor errors or credential text."""


class JsonRpcTransport(Protocol):
    def request(
        self, payload: dict[str, Any], *, timeout_seconds: int, max_response_bytes: int,
    ) -> dict[str, Any]: ...


def _normalized_read(operation):
    @wraps(operation)
    def wrapped(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError, OSError):
            # Pydantic errors can include the rejected source value. Do not expose them.
            raise ConnectorError("invalid_source_response") from None
    return wrapped


def _number(value: Any, *, maximum: int = 2**64 - 1) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str) and _NUMBER.fullmatch(value):
        result = int(value)
    else:
        raise ValueError("Invalid numeric source field")
    if not 0 <= result <= maximum:
        raise ValueError("Source field outside bounds")
    return result


def _id(value: Any) -> str:
    result = _number(value)
    if result == 0:
        raise ValueError("Source identity must be positive")
    return str(result)


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        raise ValueError("Invalid source label")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid source label")
    return value


def _rows(result: Any, limit: int) -> list[dict[str, Any]]:
    if (not isinstance(result, list) or len(result) > limit
            or any(not isinstance(row, dict) for row in result)):
        raise ConnectorError("invalid_source_response")
    return result


def _unique(rows: list[dict[str, Any]], field: str) -> None:
    ids = [_id(row[field]) for row in rows]
    if len(ids) != len(set(ids)):
        raise ConnectorError("duplicate_source_identity")


class ZabbixConnector:
    def __init__(
        self, source: SourceIdentity, transport: JsonRpcTransport,
        *, now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        if source.provider != "zabbix":
            raise ValueError("Zabbix adapter requires a Zabbix source")
        self.source = source
        self._transport = transport
        self._now = now

    def _ref(self, kind: str, identity: Any) -> RemoteRef:
        return RemoteRef(source=self.source, object_type=kind, remote_id=_id(identity))

    def _rpc(self, method: str, params: dict[str, Any], timeout: int) -> Any:
        if method not in _READ_METHODS:
            raise ConnectorError("unsupported_operation")
        request_id = str(uuid4())
        try:
            response = self._transport.request(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                timeout_seconds=timeout, max_response_bytes=MAX_RESPONSE_BYTES,
            )
        except ConnectorError:
            raise
        except Exception:
            raise ConnectorError("source_unavailable") from None
        if (not isinstance(response, dict) or response.get("jsonrpc") != "2.0"
                or response.get("id") != request_id):
            raise ConnectorError("invalid_rpc_envelope")
        if "error" in response:
            raise ConnectorError("source_rejected_request")
        if "result" not in response:
            raise ConnectorError("invalid_rpc_envelope")
        # Defense in depth for injected transports; production transport must also
        # bound the original bytes before parsing. Never log the encoded response.
        try:
            size = len(json.dumps(response, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            raise ConnectorError("invalid_source_response") from None
        if size > MAX_RESPONSE_BYTES:
            raise ConnectorError("source_response_too_large")
        return response["result"]

    def _begin(self, scope: ReadScope) -> list[str]:
        groups = sorted({_id(value) for value in scope.group_ids}, key=int)
        self._version(scope.timeout_seconds)
        return groups

    def _version(self, timeout: int):
        version = self._rpc("apiinfo.version", {}, timeout)
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise ConnectorError("unsupported_source_version")

    @_normalized_read
    def discover_groups(self, search: str = "") -> dict:
        self._version(10)
        params = {"output": ["groupid", "name"], "sortfield": "name", "limit": 201}
        if search:
            params["search"] = {"name": _text(search, 128)}
        rows = _rows(self._rpc("hostgroup.get", params, 10), 201)
        _unique(rows, "groupid")
        return {"items": [{"id": _id(row["groupid"]), "name": _text(row["name"], 255)} for row in rows[:200]],
                "truncated": len(rows) > 200}

    @_normalized_read
    def resource_manifest(self, scope: ReadScope) -> list[str]:
        # host.get has no offset/keyset cursor. Fetch only bounded IDs once, then
        # read explicit ID batches. Never invent an unsupported hostid_from field.
        groups = self._begin(scope)
        rows = _rows(self._rpc("host.get", {"groupids": groups, "output": ["hostid"],
                    "sortfield": "hostid", "sortorder": "ASC", "limit": 10001}, scope.timeout_seconds), 10001)
        _unique(rows, "hostid")
        if len(rows) > 10000:
            raise ConnectorError("source_scope_too_large")
        return sorted((_id(row["hostid"]) for row in rows), key=int)

    @_normalized_read
    def read_resource_batch(self, scope: ReadScope, host_ids: list[str]) -> ObservationBatch[ResourceObservation]:
        ids = {_id(value) for value in host_ids}
        if not ids or len(ids) > 250 or len(ids) != len(host_ids):
            raise ConnectorError("invalid_source_request")
        groups = self._begin(scope)
        rows = _rows(self._rpc("host.get", {"groupids": groups, "hostids": sorted(ids, key=int),
            "output": ["hostid", "host", "name", "status"], "selectHostGroups": ["groupid"],
            "limit": len(ids) + 1}, scope.timeout_seconds), len(ids) + 1)
        _unique(rows, "hostid")
        for row in rows:
            membership = {_id(item["groupid"]) for item in _rows(row["hostgroups"], 1000)}
            if _id(row["hostid"]) not in ids or not membership.intersection(groups):
                raise ConnectorError("source_scope_mismatch")
        return ObservationBatch[ResourceObservation](source=self.source, fetched_at=self._now(),
            items=tuple(ResourceObservation(ref=self._ref("host", row["hostid"]),
                name=_text(row["name"] or row["host"], 255), monitoring_enabled=_number(row["status"], maximum=1) == 0)
                for row in rows), truncated=False)

    def _hosts(
        self, groups: list[str], scope: ReadScope, *, host_id: str | None = None,
    ) -> list[dict[str, Any]]:
        params = {
            "groupids": groups,
            "output": ["hostid", "host", "name", "status"],
            "selectHostGroups": ["groupid"],
            "sortfield": "hostid", "sortorder": "ASC",
            "limit": 2 if host_id else scope.limit + 1,
        }
        if host_id is not None:
            params["hostids"] = [host_id]
        rows = _rows(self._rpc("host.get", params, scope.timeout_seconds), params["limit"])
        _unique(rows, "hostid")
        for row in rows:
            host_groups = {_id(item["groupid"]) for item in _rows(row["hostgroups"], 1000)}
            if not host_groups.intersection(groups) or (host_id and _id(row["hostid"]) != host_id):
                raise ConnectorError("source_scope_mismatch")
        return rows

    @_normalized_read
    def discover_resources(self, scope: ReadScope) -> ObservationBatch[ResourceObservation]:
        groups = self._begin(scope)
        rows = self._hosts(groups, scope)
        items = tuple(ResourceObservation(
            ref=self._ref("host", row["hostid"]),
            name=_text(row["name"] or row["host"], 255),
            monitoring_enabled=_number(row["status"], maximum=1) == 0,
        ) for row in rows[:scope.limit])
        return ObservationBatch[ResourceObservation](
            source=self.source, fetched_at=self._now(), items=items,
            truncated=len(rows) > scope.limit,
        )

    @_normalized_read
    def read_alerts(self, scope: ReadScope) -> ObservationBatch[AlertObservation]:
        groups = self._begin(scope)
        rows = _rows(self._rpc("problem.get", {
            "groupids": groups, "source": 0, "object": 0, "recent": True,
            "output": ["eventid", "objectid", "source", "object", "name", "severity",
                       "clock", "acknowledged", "suppressed", "r_eventid", "r_clock"],
            "sortfield": "eventid", "sortorder": "ASC", "limit": scope.limit + 1,
        }, scope.timeout_seconds), scope.limit + 1)
        _unique(rows, "eventid")
        items = []
        for row in rows[:scope.limit]:
            if _number(row["source"]) != 0 or _number(row["object"]) != 0:
                raise ConnectorError("unsupported_source_object")
            recovery_id = _number(row["r_eventid"])
            recovery_clock = _number(row["r_clock"])
            if bool(recovery_id) != bool(recovery_clock):
                raise ConnectorError("invalid_recovery_evidence")
            items.append(AlertObservation(
                ref=self._ref("problem", row["eventid"]),
                # A trigger is not a host. Binding its affected resources is a
                # later reconciliation operation, never an IP/name guess here.
                subject=self._ref("trigger", row["objectid"]),
                title=_text(row["name"], 1024),
                native_severity=str(_number(row["severity"], maximum=5)),
                state="resolved" if recovery_id else "open",
                acknowledged=bool(_number(row["acknowledged"], maximum=1)),
                suppressed=bool(_number(row["suppressed"], maximum=1)),
                occurred_at=datetime.fromtimestamp(_number(row["clock"]), UTC),
                resolved_at=datetime.fromtimestamp(recovery_clock, UTC) if recovery_id else None,
                recovery_ref=self._ref("event", recovery_id) if recovery_id else None,
            ))
        return ObservationBatch[AlertObservation](
            source=self.source, fetched_at=self._now(), items=tuple(items),
            truncated=len(rows) > scope.limit,
        )

    @_normalized_read
    def active_event_manifest(self, scope: ReadScope) -> list[str]:
        groups = self._begin(scope)
        rows = _rows(self._rpc("problem.get", {"groupids": groups, "source": 0, "object": 0,
            "output": ["eventid"], "sortfield": "eventid", "sortorder": "ASC", "limit": 10001},
            scope.timeout_seconds), 10001)
        _unique(rows, "eventid")
        if len(rows) > 10000:
            raise ConnectorError("source_scope_too_large")
        return sorted((_id(row["eventid"]) for row in rows), key=int)

    @_normalized_read
    def read_events(self, scope: ReadScope, *, event_ids: list[str] | None = None,
                    after: str = "0", since: datetime | None = None) -> ObservationBatch[AlertObservation]:
        """Explicit old-event reconciliation or bounded forward event paging.

        event.get retains recovery references beyond problem.get's recent window.
        A missing row is unknown, never proof of recovery. No acknowledge writes.
        """
        groups = self._begin(scope)
        params = {"groupids": groups, "source": 0, "object": 0, "value": 1,
            "output": ["eventid", "objectid", "source", "object", "value", "name", "severity",
                       "clock", "acknowledged", "suppressed", "r_eventid"],
            "selectHosts": ["hostid"], "sortfield": "eventid", "sortorder": "ASC", "limit": 101}
        requested = None
        if event_ids is not None:
            requested = {_id(value) for value in event_ids}
            if not requested or len(requested) > 100 or len(requested) != len(event_ids):
                raise ConnectorError("invalid_source_request")
            params.update(eventids=sorted(requested, key=int), limit=len(requested) + 1)
        else:
            cursor = _number(after)
            if cursor == 2**64 - 1:
                return ObservationBatch[AlertObservation](source=self.source, fetched_at=self._now(), items=(), truncated=False)
            if since is None or since.tzinfo is None:
                raise ConnectorError("invalid_source_request")
            params.update(eventid_from=str(cursor + 1), time_from=max(0, math.floor(since.timestamp())))
        rows = _rows(self._rpc("event.get", params, scope.timeout_seconds), params["limit"])
        _unique(rows, "eventid")
        for row in rows:
            if (_number(row["source"]) != 0 or _number(row["object"]) != 0 or _number(row["value"]) != 1
                or (requested is not None and _id(row["eventid"]) not in requested)
                or (requested is None and (_number(row["eventid"]) <= cursor or _number(row["clock"]) < params["time_from"]))):
                raise ConnectorError("source_scope_mismatch")
        rows.sort(key=lambda row: _number(row["eventid"]))
        truncated = requested is None and len(rows) > 100
        rows = rows[:100]
        host_ids = set()
        for row in rows:
            hosts = _rows(row["hosts"], 250)
            _unique(hosts, "hostid")
            host_ids.update(_id(host["hostid"]) for host in hosts)
        if len(host_ids) > 250:
            raise ConnectorError("source_scope_too_large")
        hosts = {}
        if host_ids:
            # Current membership and source names, not untrusted trigger labels.
            raw = _rows(self._rpc("host.get", {"groupids": groups, "hostids": sorted(host_ids, key=int),
                "output": ["hostid", "host", "name", "status"], "selectHostGroups": ["groupid"],
                "limit": len(host_ids) + 1}, scope.timeout_seconds), len(host_ids) + 1)
            _unique(raw, "hostid")
            for host in raw:
                if (_id(host["hostid"]) not in host_ids
                    or not {_id(group["groupid"]) for group in _rows(host["hostgroups"], 1000)}.intersection(groups)):
                    raise ConnectorError("source_scope_mismatch")
                hosts[_id(host["hostid"])] = ResourceObservation(ref=self._ref("host", host["hostid"]),
                    name=_text(host["name"] or host["host"], 255), monitoring_enabled=_number(host["status"], maximum=1) == 0)
        recovery_ids = {_id(row["r_eventid"]) for row in rows if _number(row["r_eventid"])}
        recoveries = {}
        if recovery_ids:
            raw = _rows(self._rpc("event.get", {"eventids": sorted(recovery_ids, key=int), "source": 0, "object": 0,
                "output": ["eventid", "objectid", "source", "object", "value", "clock"],
                "limit": len(recovery_ids) + 1}, scope.timeout_seconds), len(recovery_ids) + 1)
            _unique(raw, "eventid")
            for recovery in raw:
                if (_id(recovery["eventid"]) not in recovery_ids or _number(recovery["source"]) != 0
                    or _number(recovery["object"]) != 0 or _number(recovery["value"]) != 0):
                    raise ConnectorError("invalid_recovery_evidence")
                recoveries[_id(recovery["eventid"])] = recovery
            if set(recoveries) != recovery_ids:
                raise ConnectorError("invalid_recovery_evidence")
        items = []
        for row in rows:
            recovery = recoveries.get(str(row["r_eventid"]))
            if recovery and _id(recovery["objectid"]) != _id(row["objectid"]):
                raise ConnectorError("invalid_recovery_evidence")
            ids = [_id(host["hostid"]) for host in row["hosts"]]
            # Multi-host/out-of-scope triggers are never reduced to one guessed asset.
            resources = tuple(hosts[identifier] for identifier in ids) if all(identifier in hosts for identifier in ids) else ()
            items.append(AlertObservation(ref=self._ref("problem", row["eventid"]), subject=self._ref("trigger", row["objectid"]),
                title=_text(row["name"], 1024), native_severity=str(_number(row["severity"], maximum=5)),
                state="resolved" if recovery else "open", acknowledged=bool(_number(row["acknowledged"], maximum=1)),
                suppressed=bool(_number(row["suppressed"], maximum=1)),
                occurred_at=datetime.fromtimestamp(_number(row["clock"]), UTC),
                resolved_at=datetime.fromtimestamp(_number(recovery["clock"]), UTC) if recovery else None,
                recovery_ref=self._ref("event", recovery["eventid"]) if recovery else None, resources=resources))
        return ObservationBatch[AlertObservation](source=self.source, fetched_at=self._now(), items=tuple(items), truncated=truncated)

    @_normalized_read
    def list_metrics(self, scope: ReadScope, host_id: str):
        groups = self._begin(scope)
        host_id = _id(host_id)
        if len(self._hosts(groups, scope, host_id=host_id)) != 1:
            raise ConnectorError("resource_unavailable_in_scope")
        rows = _rows(self._rpc("item.get", {"groupids": groups, "hostids": [host_id],
            "filter": {"value_type": [0, 3]}, "output": ["itemid", "hostid", "name", "value_type", "units"],
            "sortfield": "itemid", "sortorder": "ASC", "limit": 51}, scope.timeout_seconds), 51)
        _unique(rows, "itemid")
        items = []
        for row in rows[:50]:
            if _id(row["hostid"]) != host_id or _number(row["value_type"]) not in {0, 3}:
                raise ConnectorError("metric_scope_or_type_mismatch")
            items.append({"metric_id": _id(row["itemid"]), "name": _text(row["name"], 255),
                "value_type": "float" if _number(row["value_type"]) == 0 else "uint",
                "unit": _text(row["units"], 255) if row.get("units") else None})
        return {"items": items, "truncated": len(rows) > 50}

    @_normalized_read
    def query_history(self, scope: ReadScope, query: HistoryQuery) -> ObservationBatch[MetricSample]:
        groups = self._begin(scope)
        host_id, item_id = _id(query.resource_id), _id(query.metric_id)
        if len(self._hosts(groups, scope, host_id=host_id)) != 1:
            raise ConnectorError("resource_unavailable_in_scope")
        value_type = 0 if query.value_type == "float" else 3
        items = _rows(self._rpc("item.get", {
            "groupids": groups, "hostids": [host_id], "itemids": [item_id],
            "output": ["itemid", "hostid", "value_type", "units"], "limit": 2,
        }, scope.timeout_seconds), 2)
        if len(items) != 1:
            raise ConnectorError("metric_unavailable_in_scope")
        item = items[0]
        if (_id(item["itemid"]) != item_id or _id(item["hostid"]) != host_id
                or _number(item["value_type"]) != value_type):
            raise ConnectorError("metric_scope_or_type_mismatch")
        unit = None if item.get("units") in (None, "") else _text(item["units"], 255)
        start_key = (math.floor(query.start.timestamp()), query.start.microsecond * 1000)
        end_key = (math.floor(query.end.timestamp()), query.end.microsecond * 1000)
        rows = _rows(self._rpc("history.get", {
            "hostids": [host_id], "itemids": [item_id], "history": value_type,
            "time_from": start_key[0], "time_till": end_key[0],
            "output": ["itemid", "clock", "ns", "value"],
            "sortfield": ["clock", "ns"], "sortorder": "ASC", "limit": query.limit + 1,
        }, scope.timeout_seconds), query.limit + 1)
        samples = []
        seen = set()
        for row in rows:
            if _id(row["itemid"]) != item_id:
                raise ConnectorError("metric_scope_or_type_mismatch")
            seconds = _number(row["clock"])
            timestamp = datetime.fromtimestamp(seconds, UTC)
            ns = _number(row["ns"], maximum=999_999_999)
            # Whole-second API bounds may return samples outside a subsecond
            # caller window. Filter them without pretending the page was complete.
            if not start_key[0] <= seconds <= end_key[0]:
                raise ConnectorError("source_time_range_mismatch")
            if not start_key <= (seconds, ns) <= end_key:
                continue
            key = (timestamp, ns)
            if key in seen:
                raise ConnectorError("duplicate_source_sample")
            seen.add(key)
            if value_type == 3:
                value = _number(row["value"])
            else:
                raw = row["value"]
                if type(raw) not in {str, int, float}:
                    raise ValueError("Invalid metric value")
                value = float(raw)
                if not math.isfinite(value):
                    raise ValueError("Non-finite metric value")
            samples.append(MetricSample(
                metric=self._ref("item", item_id), resource=self._ref("host", host_id),
                timestamp=timestamp, nanoseconds=ns, value=value, unit=unit,
            ))
        samples.sort(key=lambda sample: (sample.timestamp, sample.nanoseconds))
        return ObservationBatch[MetricSample](
            source=self.source, fetched_at=self._now(), items=tuple(samples[:query.limit]),
            truncated=len(rows) > query.limit,
        )
