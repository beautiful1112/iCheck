# Monitoring bridge template contract

An engineer can wrap a monitoring product's read API with this small contract,
share the connector requirement with operation packages, and bind each
installation to its own protected bridge connection. The implementation must
enforce the caller's group scope at the source. Do not expose arbitrary query,
command, URL or write operations.

## Wire protocol

iCheck POSTs JSON to the single configured HTTPS endpoint using its saved bearer
token. The endpoint must return `application/json`, HTTP 200 and identity content
encoding. Redirects, untrusted TLS, secret reflection, responses above 2 MB and
requests beyond the 30-second operation budget are rejected.

Every request has:

```json
{
  "protocol": "icheck.monitoring-bridge/v1",
  "operation": "resources",
  "scope": {"group_ids": ["2"], "limit": 20, "timeout_seconds": 10},
  "ids": [],
  "after": "0",
  "since": null,
  "search": "",
  "query": null
}
```

Every response has exactly:

```json
{
  "protocol": "icheck.monitoring-bridge/v1",
  "operation": "resources",
  "items": [
    {"id": "10", "name": "Example router", "monitoring_enabled": true, "group_ids": ["2"]}
  ],
  "truncated": false
}
```

`scope` is absent/null only for group metadata discovery. IDs are stable, positive
decimal strings of at most 20 digits within unsigned 64-bit range. Do not reuse
event IDs. Bridges for products using UUIDs need a durable, local numeric mapping;
do not generate a fresh mapping on each request.

## Fixed operations

| Operation | Request | Response items / bounds |
| --- | --- | --- |
| `groups` | `search` | `{id,name}`, at most 200; report truncation |
| `manifest` | group scope | Resource ID strings, at most 10,000; truncated manifests are refused |
| `resources` | scope; optional explicit `ids` | `{id,name,monitoring_enabled,group_ids}`; preview limit or at most 250 explicit IDs |
| `active` | scope | Active event ID strings, at most 10,000 |
| `events` | explicit `ids`, or exclusive `after` plus inclusive UTC `since` | At most 100 events; forward reads sorted by numeric event ID |
| `metrics` | scope and one resource ID in `ids` | At most 50 `{metric_id,name,value_type,unit}` records |
| `history` | scope and `query` | At most requested limit of numeric samples |

An explicit-ID batch may omit inaccessible records, but must never substitute a
different record. Resource group membership is checked again from each response.
An incomplete explicit batch must not be labeled complete. Empty data never
authorizes deletion or inferred recovery.

### Event item

```json
{
  "id": "100",
  "subject_id": "300",
  "title": "Example interface unavailable",
  "native_severity": "4",
  "state": "open",
  "acknowledged": false,
  "suppressed": false,
  "occurred_at": "2026-10-20T00:00:00Z",
  "resolved_at": null,
  "recovery_id": null,
  "resources": [
    {"id": "10", "name": "Example router", "monitoring_enabled": true, "group_ids": ["2"]}
  ]
}
```

Bridge severity uses a normalized 0–5 scale: 0–1 informational, 2–3 warning,
4–5 critical. `suppressed` must reflect effective source muting, including inherited
silence. `state=resolved` requires both a source recovery ID and a timezone-aware
recovery time at or after the trigger. Acknowledgement is independent.
`subject_id` and trigger time must remain unchanged throughout an episode.

The source must retain or reconcile historical recovery records, not just its
recent-open-alert list. Return unknown/missing evidence when retention prevents
verification. Do not invent a recovery from an absent device or active event.
Do not collapse multi-resource events to one guessed resource.

### History

`query` contains `resource_id`, `metric_id`, `value_type` (`float` or `uint`),
timezone-aware `start` and `end`, and `limit`. Windows are positive and at most
31 days; the adapter allows at most 2,000 samples and AI tools at most 500.

Each sample contains `resource_id`, `metric_id`, `timestamp`, `nanoseconds`,
numeric `value` and nullable `unit`. Keep unsigned counters as JSON integers,
not floating point. Reject non-finite values, duplicate timestamp/nanosecond
pairs and out-of-window samples. Truncation must be explicit.

## Webhooks

Vendor webhooks should update the bridge's durable source state or request an
authenticated iCheck recheck using the connection's `/notify` endpoint. They
must not bypass source verification, activate a feed or directly submit AI
instructions. Use the original product API to verify state where the webhook
does not provide authenticated, durable recovery semantics.

The executable client and schemas are in
`backend/icheck/monitoring_connectors/bridge.py`. Synthetic contract examples are
in `tests/test_orion_bridge_connectors.py`. The bridge does not require Prometheus.
