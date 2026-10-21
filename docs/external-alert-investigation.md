# External alerts and AI investigation

Included in engineering prerelease r19.28. Live vendor qualification remains pending.
The first implementation supports read-only Zabbix 7.0/7.4 protocol targets.
SolarWinds and other providers remain separate planned adapters.

## Operator workflow

1. Open **Integrations**, save the Zabbix connection, choose its host groups and
   synchronize inventory.
2. Use **Asset mapping** to review links to existing iCheck assets. No duplicate
   devices or native polling jobs are created.
3. Open the connection's **External alerts** tab and enable its alert feed.
   This approves periodic read-only Zabbix API requests. The default is off;
   the interval is 60–3,600 seconds.
4. If unattended diagnosis is wanted, enable **AI Settings → Automatic
   investigation** separately. Its existing authority checks, severity/age
   filters, concurrency limits, daily limits and model/tool budgets apply.
   Enabling the feed alone never enables the AI policy.
5. Inspect the retained source events, source acknowledgement/suppression,
   mapping state, last successful read and any error. **View native alert**
   opens the corresponding iCheck episode. **Silence AI for this episode**
   stops automatic investigation without changing Zabbix notifications.
   **Close in iCheck and stop AI**, on the native alert page, closes the local
   episode without changing Zabbix or claiming that the fault recovered.

Opening or refreshing either page reads local records only. Source text is
untrusted evidence, not instructions or permission to operate infrastructure.
Feed administration requires a signed-in human with global metric/alert management
permission. Evidence tools independently enforce current alert and device access.

## Stop semantics

| Observation or operator action | iCheck alert | Automatic investigation |
| --- | --- | --- |
| Open source problem | Open | Eligible only under the separate standing policy |
| Source acknowledgement | Acknowledged; fault remains | Continues |
| Zabbix suppression, including maintenance/manual suppression | Not resolved merely because it is suppressed | Stops |
| Explicit source recovery/closure with recovery-event evidence | Resolved | Stops |
| Local “Silence AI” | Retained, not falsely resolved | Stops |
| Local closure | Resolved locally; source unchanged | Stops |
| Missing event, unavailable source, stale evidence, disabled feed or changed scope/mapping | Retained; no inferred recovery | Further automatic work is blocked/stopped |

Local stop actions and source-poll cancellation are transactional. Queued or
waiting-for-approval work is cancelled immediately. Running work receives a
cancellation request; no further model/tool/lease operation is admitted after the
stop boundary. A request already in flight may finish.

The runtime also re-reads the triggering event at the source before worker claim
and subsequent execution boundaries; it does not wait for the background poll to
notice a new suppression. Reads are bounded, not an instantaneous push guarantee.
A suppression that begins and ends entirely between observations cannot be
detected retrospectively by this polling implementation.

Stopped or previously admitted episodes never restart automatically after
unsilencing, reconnection or reappearance. A new source problem ID is a new
episode. An explicitly requested manual follow-up remains a separate user action.
Each external episode has its own investigation group so another alert on the
same device cannot bypass that episode's silence boundary.

## Identity, reconciliation and evidence

Event identity is `(tenant, region, connection, source event ID)`, never an IP,
display name or trigger ID alone. The connector reads the trigger's affected
host IDs and rechecks their current group membership and monitoring state.
Only a single affected host with a current, reviewed canonical asset binding
can produce a native alert. Multi-host, missing-host and unmapped observations
remain visible as source evidence; the implementation does not guess an owner.
Changing a binding never retargets a retained alert episode.

The initial active-problem manifest is capped at 10,000 IDs. Explicit pages
contain at most 100 events and 250 host identities. Forward event-ID paging
alternates with reconciliation of retained unresolved events, oldest checked
first. The event cursor, observation, projection and stop state commit together;
a crash rolls back the batch. An inventory scan is never recovery evidence.

Historical recovery is fetched through `event.get` and its explicit `r_eventid`,
not inferred from disappearing `problem.get` results. The recovery event must
match the same trigger and a valid recovery time. Missing, truncated or
contradictory evidence does not resolve an alert. Source event timestamps are
retained; importing old problems does not backfill an already-enabled AI policy.
Zabbix severities 0–1 map to informational, 2–3 to warning, and 4–5 to critical.
Acknowledgement is never converted to recovery.

The existing Tool Registry includes three read-only tools:

- `integrations.alerts.read`: retained source-attributed alert evidence.
- `integrations.metrics.list`: up to 50 numeric items for the alert's reviewed
  source host; explicitly reports truncation.
- `integrations.history.query`: exact host/item/type validation, an aware time
  window of at most 31 days, and at most 500 samples per AI call. History stays
  in Zabbix; it is not copied into Prometheus or a second time-series store.

Metric discovery/history recheck current source status and scope. Missing
permissions, a changed asset identity or an unavailable source fails closed.
No source acknowledge/write API, device change, auto-remediation, webhook ingress,
external metric dashboard translation or SolarWinds qualification is included.
Retained event history is not automatically purged in this slice.

Protocol references:
[Zabbix event.get](https://www.zabbix.com/documentation/7.0/en/manual/api/reference/event/get)
and [event object](https://www.zabbix.com/documentation/7.0/en/manual/api/reference/event/object).
Fixtures validate the local contract; these references do not replace live
acceptance against each supported vendor version.

## Native deployment requirements

This development task does not change the running server. For a separately
authorized rollout:

1. Back up database/configuration and drain API and workers before migration.
2. Apply additive migration `e8k0m2p4r6t9 → f9l1n3q5s7u0`. The new feed/event
   tables start empty with namespace RLS. Downgrade refuses to discard history.
3. Provision the dedicated `icheck-integration-alert` system account and
   `integration-alert-worker` PostgreSQL profile using the reviewed grant CLI.
   Update the existing workflow-dispatch role's read grants and initialize the
   built-in tool catalog. Do not substitute the database owner for a worker.
4. Install `icheck-integration-alert-worker.service` and a protected environment
   based on `deploy/systemd/integration-alert-worker.env.example`. The systemd
   credential mount uses existing server key custody; no token belongs in the
   environment example. Copy only administrator-approved monitoring HTTPS
   origins to both the API and alert worker configuration.
5. Deploy the paired API/GUI, restart and verify service health, migration head,
   role boundaries, sign-in and the new tab. Feeds and the AI policy remain off
   unless explicitly enabled.

The worker can update source progress and cancel automatic work but cannot
enable a feed, approve asset bindings, rotate credentials, create an AI execution,
or read device credentials. It uses PostgreSQL row locks with `SKIP LOCKED`;
source requests have a 30-second transport budget and 2 MB response limit.
Known source failures wait for the configured interval before retrying.
Verification uses a temporary PostgreSQL cluster and synthetic source data, not
the running installation.
