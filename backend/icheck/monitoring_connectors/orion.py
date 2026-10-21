"""Read-only SWIS connector. Fixed queries; no arbitrary SWQL or write verbs."""
from datetime import UTC, datetime
import json
import math
from typing import Literal

from pydantic import AwareDatetime, Field

from .contracts import (ConnectorModel, SourceIdentity, RemoteRef, ResourceObservation,
                        AlertObservation, ObservationBatch, MetricSample)
from .zabbix import ConnectorError, MAX_RESPONSE_BYTES, _id, _number, _text, _rows, _unique, _normalized_read


METRICS = {
    "response_time": ("AvgResponseTime", "Average response time", "ms"),
    "packet_loss": ("PercentLoss", "Packet loss", "%"),
    "availability": ("Availability", "Availability", "%"),
}


class QueryRequest(ConnectorModel):
    operation: Literal["groups", "manifest", "resources", "active", "events", "recoveries", "suppression", "history"]
    groups: tuple[str, ...] = Field(default=(), max_length=100)
    ids: tuple[str, ...] = Field(default=(), max_length=250)
    uris: tuple[str, ...] = Field(default=(), max_length=100)
    limit: int = Field(default=101, ge=1, le=10001, strict=True)
    search: str = Field(default="", max_length=128)
    after: str = "0"
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    metric: Literal["response_time", "packet_loss", "availability"] = "response_time"


def compile_query(payload):
    request = QueryRequest.model_validate(payload)
    params = {"groups": [int(_id(v)) for v in request.groups], "ids": [int(_id(v)) for v in request.ids]}
    if request.operation == "suppression":
        if not request.uris or any(not uri.startswith("swis://") or len(uri) > 2048
                                   or any(ord(c) < 32 for c in uri) for uri in request.uris):
            raise ConnectorError("invalid_source_request")
        return [list(request.uris)]
    if request.operation == "groups":
        params["search"] = "%" + request.search + "%"
        query = f"SELECT TOP {request.limit} ContainerID AS id, Name AS name FROM Orion.Container WHERE Name LIKE @search ORDER BY Name"
        return {"query": query, "parameters": params}
    if not params["groups"]:
        raise ConnectorError("invalid_source_request")
    # The current group membership is part of every resource/evidence read.
    member = ("n.NodeID IN (SELECT MemberPrimaryID FROM Orion.ContainerMembers "
              "WHERE ContainerID IN @groups AND MemberEntityType = 'Orion.Nodes')")
    if request.operation in {"manifest", "resources"}:
        fields = "n.NodeID AS id" if request.operation == "manifest" else (
            "n.NodeID AS id, n.Caption AS name, n.UnManaged AS unmanaged")
        query = f"SELECT TOP {request.limit} {fields} FROM Orion.Nodes n WHERE {member}"
        if params["ids"]:
            query += " AND n.NodeID IN @ids"
        query += " ORDER BY n.NodeID"
    elif request.operation in {"events", "active"}:
        fields = "h.AlertHistoryID AS id" if request.operation == "active" else (
            "h.AlertHistoryID AS id, h.AlertActiveID AS episode, h.AlertObjectID AS subject, "
            "h.TimeStamp AS occurred, c.Name AS title, c.Severity AS severity, c.Enabled AS enabled, "
            "o.EntityUri AS uri, o.EntityType AS entity_type, n.NodeID AS node_id, "
            "a.AlertActiveID AS active_id, a.Acknowledged AS acknowledged")
        query = (f"SELECT TOP {request.limit} {fields} FROM Orion.AlertHistory h "
                 "JOIN Orion.AlertObjects o ON o.AlertObjectID=h.AlertObjectID "
                 "JOIN Orion.AlertConfigurations c ON c.AlertID=o.AlertID "
                 "JOIN Orion.Nodes n ON n.NodeID=o.RelatedNodeId "
                 "LEFT JOIN Orion.AlertActive a ON a.AlertActiveID=h.AlertActiveID AND a.AlertObjectID=h.AlertObjectID "
                 f"WHERE h.EventType=0 AND o.EntityType='Orion.Nodes' AND {member}")
        if request.operation == "active":
            query += " AND a.AlertActiveID IS NOT NULL"
        elif params["ids"]:
            query += " AND h.AlertHistoryID IN @ids"
        else:
            if request.start is None:
                raise ConnectorError("invalid_source_request")
            params.update(after=_number(request.after), start=request.start.isoformat())
            query += " AND h.AlertHistoryID>@after AND h.TimeStamp>=@start"
        query += " ORDER BY h.AlertHistoryID"
    elif request.operation == "recoveries":
        if not params["ids"]:
            raise ConnectorError("invalid_source_request")
        query = (f"SELECT TOP {request.limit} h.AlertHistoryID AS id, h.AlertActiveID AS episode, "
                 "h.AlertObjectID AS subject, h.TimeStamp AS occurred, h.EventType AS event_type "
                 "FROM Orion.AlertHistory h JOIN Orion.AlertObjects o ON o.AlertObjectID=h.AlertObjectID "
                 "JOIN Orion.Nodes n ON n.NodeID=o.RelatedNodeId "
                 f"WHERE h.AlertActiveID IN @ids AND h.EventType IN (1,8) AND {member} ORDER BY h.AlertHistoryID")
    else:
        if len(params["ids"]) != 1 or request.start is None or request.end is None:
            raise ConnectorError("invalid_source_request")
        column = METRICS[request.metric][0]
        params.update(start=request.start.isoformat(), end=request.end.isoformat())
        query = (f"SELECT TOP {request.limit} r.NodeID AS node_id, r.DateTime AS timestamp, r.{column} AS value "
                 "FROM Orion.ResponseTime r JOIN Orion.Nodes n ON n.NodeID=r.NodeID "
                 f"WHERE {member} AND n.NodeID IN @ids AND r.DateTime>=@start AND r.DateTime<=@end "
                 "AND r.Archive=0 ORDER BY r.DateTime")
    return {"query": query, "parameters": params}


def _date(value):
    # SWIS DateTime values are UTC, including ISO responses without a suffix.
    if not isinstance(value, str):
        raise ValueError("Invalid SWIS time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("Invalid source boolean")
    return value


class OrionConnector:
    def __init__(self, source: SourceIdentity, transport, *, now=lambda: datetime.now(UTC)):
        if source.provider != "solarwinds_orion":
            raise ValueError("Orion adapter requires an Orion source")
        self.source, self.transport, self.now = source, transport, now

    def ref(self, kind, identity):
        return RemoteRef(source=self.source, object_type=kind, remote_id=str(identity))

    def batch(self, items, truncated=False):
        return ObservationBatch(source=self.source, fetched_at=self.now(), items=tuple(items), truncated=truncated)

    def query(self, operation, *, groups=(), timeout=10, limit=101, **kwargs):
        payload = QueryRequest(operation=operation, groups=tuple(groups), limit=limit, **kwargs).model_dump(mode="json")
        compile_query(payload)  # Validate even injected transports.
        try:
            response = self.transport.request(payload, timeout_seconds=timeout, max_response_bytes=MAX_RESPONSE_BYTES)
        except ConnectorError:
            raise
        except Exception:
            raise ConnectorError("source_unavailable") from None
        if len(json.dumps(response, allow_nan=False).encode()) > MAX_RESPONSE_BYTES:
            raise ConnectorError("source_response_too_large")
        if not isinstance(response, dict) or "results" not in response:
            raise ConnectorError("invalid_source_response")
        return _rows(response["results"], limit)

    @_normalized_read
    def discover_groups(self, search=""):
        rows = self.query("groups", search=search, limit=201)
        _unique(rows, "id")
        return {"items": [{"id": _id(r["id"]), "name": _text(r["name"], 255)} for r in rows[:200]],
                "truncated": len(rows) > 200}

    @_normalized_read
    def resource_manifest(self, scope):
        rows = self.query("manifest", groups=scope.group_ids, timeout=scope.timeout_seconds, limit=10001)
        _unique(rows, "id")
        if len(rows) > 10000:
            raise ConnectorError("source_scope_too_large")
        return sorted((_id(r["id"]) for r in rows), key=int)

    def _resources(self, scope, ids=()):
        if len(ids) > 250 or len(set(ids)) != len(ids):
            raise ConnectorError("invalid_source_request")
        rows = self.query("resources", groups=scope.group_ids, timeout=scope.timeout_seconds,
                          limit=len(ids) + 1 if ids else scope.limit + 1, ids=tuple(ids))
        _unique(rows, "id")
        if ids and any(_id(r["id"]) not in ids for r in rows):
            raise ConnectorError("source_scope_mismatch")
        return [ResourceObservation(ref=self.ref("node", _id(r["id"])), name=_text(r["name"], 255),
                                    monitoring_enabled=not _boolean(r["unmanaged"])) for r in rows]

    @_normalized_read
    def read_resource_batch(self, scope, host_ids):
        if not host_ids:
            raise ConnectorError("invalid_source_request")
        return self.batch(self._resources(scope, [_id(v) for v in host_ids]))

    @_normalized_read
    def discover_resources(self, scope):
        rows = self._resources(scope)
        return self.batch(rows[:scope.limit], len(rows) > scope.limit)

    @_normalized_read
    def active_event_manifest(self, scope):
        rows = self.query("active", groups=scope.group_ids, timeout=scope.timeout_seconds, limit=10001)
        _unique(rows, "id")
        if len(rows) > 10000:
            raise ConnectorError("source_scope_too_large")
        return sorted((_id(r["id"]) for r in rows), key=int)

    @_normalized_read
    def read_events(self, scope, *, event_ids=None, after="0", since=None):
        if event_ids is not None and (not event_ids or len(event_ids) > 100 or len(set(event_ids)) != len(event_ids)):
            raise ConnectorError("invalid_source_request")
        rows = self.query("events", groups=scope.group_ids, timeout=scope.timeout_seconds,
                          ids=tuple(event_ids or ()), after=after, start=since)
        _unique(rows, "id")
        for row in rows:
            if (row["entity_type"] != "Orion.Nodes" or
                (event_ids is not None and _id(row["id"]) not in event_ids) or
                (event_ids is None and (_number(row["id"]) <= _number(after) or _date(row["occurred"]) < since))):
                raise ConnectorError("source_scope_mismatch")
        rows.sort(key=lambda r: _number(r["id"]))
        truncated, rows = len(rows) > 100, rows[:100]
        if not rows:
            return self.batch(())
        nodes = {_id(r["node_id"]) for r in rows}
        resources = {r.ref.remote_id: r for r in self._resources(scope, sorted(nodes, key=int))}
        episodes = {_id(r["episode"]) for r in rows}
        recovered = self.query("recoveries", groups=scope.group_ids, timeout=scope.timeout_seconds,
                               ids=tuple(sorted(episodes, key=int)), limit=201)
        _unique(recovered, "id")
        if len(recovered) > 200:
            raise ConnectorError("source_scope_too_large")
        recovery = {}
        for r in recovered:
            if _id(r["episode"]) not in episodes or _number(r["event_type"]) not in {1, 8}:
                raise ConnectorError("invalid_recovery_evidence")
            recovery.setdefault((_id(r["episode"]), _id(r["subject"])), r)
        uris = tuple(sorted({_text(r["uri"], 2048) for r in rows}))
        states = self.query("suppression", uris=uris, limit=100)
        suppression = {}
        for state in states:
            uri = state["EntityUri"]
            if uri not in uris or uri in suppression:
                raise ConnectorError("source_scope_mismatch")
            suppression[uri] = _number(state["SuppressionMode"], maximum=4) in {1, 2}
        if set(suppression) != set(uris):
            raise ConnectorError("invalid_source_response")
        items = []
        for row in rows:
            episode, subject = _id(row["episode"]), _id(row["subject"])
            reset = recovery.get((episode, subject))
            if reset and (_number(reset["id"]) <= _number(row["id"]) or _date(reset["occurred"]) < _date(row["occurred"])):
                raise ConnectorError("invalid_recovery_evidence")
            if row["active_id"] is not None and _id(row["active_id"]) != episode:
                raise ConnectorError("source_scope_mismatch")
            if reset and row["active_id"] is not None:
                raise ConnectorError("invalid_recovery_evidence")
            # Missing active rows are unknown, never fabricated recoveries.
            if reset is None and row["active_id"] is None:
                continue
            node = resources.get(_id(row["node_id"]))
            items.append(AlertObservation(ref=self.ref("problem", _id(row["id"])),
                subject=self.ref("alert_object", subject), title=_text(row["title"], 1024),
                native_severity=str(_number(row["severity"], maximum=4)),
                state="resolved" if reset else "open",
                acknowledged=_boolean(row["acknowledged"]) if row["active_id"] is not None else False,
                suppressed=suppression[row["uri"]] or not _boolean(row["enabled"]) or (node is not None and not node.monitoring_enabled),
                occurred_at=_date(row["occurred"]), resolved_at=_date(reset["occurred"]) if reset else None,
                recovery_ref=self.ref("event", _id(reset["id"])) if reset else None,
                resources=(node,) if node else ()))
        return self.batch(items, truncated)

    def read_alerts(self, scope):
        ids = self.active_event_manifest(scope)
        result = self.read_events(scope, event_ids=ids[:100]) if ids else self.batch(())
        return result.model_copy(update={"truncated": result.truncated or len(ids) > 100})

    @_normalized_read
    def list_metrics(self, scope, host_id):
        if len(self._resources(scope, [_id(host_id)])) != 1:
            raise ConnectorError("resource_unavailable_in_scope")
        return {"items": [{"metric_id": key, "name": value[1], "value_type": "float", "unit": value[2]}
                          for key, value in METRICS.items()], "truncated": False}

    @_normalized_read
    def query_history(self, scope, query):
        self.list_metrics(scope, query.resource_id)
        if query.metric_id not in METRICS or query.value_type != "float":
            raise ConnectorError("metric_scope_or_type_mismatch")
        rows = self.query("history", groups=scope.group_ids, timeout=scope.timeout_seconds,
                          ids=(query.resource_id,), metric=query.metric_id, start=query.start, end=query.end,
                          limit=query.limit + 1)
        samples, seen = [], set()
        for row in rows:
            timestamp = _date(row["timestamp"])
            if _id(row["node_id"]) != query.resource_id or not query.start <= timestamp <= query.end:
                raise ConnectorError("source_scope_mismatch")
            if timestamp in seen:
                raise ConnectorError("duplicate_source_sample")
            seen.add(timestamp)
            if type(row["value"]) not in {int, float} or not math.isfinite(row["value"]):
                raise ValueError("Invalid numeric sample")
            samples.append(MetricSample(metric=self.ref("metric", query.metric_id),
                resource=self.ref("node", query.resource_id), timestamp=timestamp,
                nanoseconds=timestamp.microsecond * 1000, value=float(row["value"]), unit=METRICS[query.metric_id][2]))
        samples.sort(key=lambda sample: sample.timestamp)
        return self.batch(samples[:query.limit], len(rows) > query.limit)
