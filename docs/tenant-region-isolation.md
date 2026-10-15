# Tenant and region isolation

Tenant and region are security boundaries in iCheck, not display filters.
Every operational request and every independently deployed worker executes in
exactly one tenant and one region.

## Identity and request selection

A persisted control-plane principal belongs to one tenant. Cross-tenant work
requires a separate principal or token. A principal may be allowed to operate
in multiple enabled regions of that tenant through `allowed_region_ids`.

Clients select the active boundary with:

```text
X-Icheck-Tenant-ID: <tenant UUID>
X-Icheck-Region-ID: <region UUID>
```

The browser keeps only these non-secret identifiers in local storage and sends
them on every API request. SSE uses the equivalent `icheck_tenant_id` and
`icheck_region_id` query selectors because the native EventSource API cannot
set custom headers. Authentication still comes from the HttpOnly session
cookie.

The browser closes its live investigation stream on a scope or session change
and refuses an old event even if the cross-tab storage notification has not
arrived yet. Server-side namespace authorization remains mandatory.

The server rejects a tenant other than the principal's fixed tenant, a disabled
or foreign region, and a region outside a non-empty `allowed_region_ids` list.
Role bindings and authorization scope are then resolved again inside the
selected region. A “global” role is global only within that active
tenant/region boundary.

## Defense in depth

Operational rows carry `tenant_id` and `region_id`. Isolation is enforced by
four independent layers:

1. Authentication validates the selected tenant and region.
2. SQLAlchemy loader criteria add the active namespace to ORM reads.
3. A flush guard rejects new rows whose namespace differs from the session.
4. PostgreSQL row-level security applies the transaction-local
   `icheck.tenant_id` and `icheck.region_id` settings.

PostgreSQL settings created with `set_config(..., true)` disappear at
transaction end. iCheck therefore reapplies them on every new transaction, not
only when the request or worker session is first created. Tests cover
cross-region reads, writes, Worker registration, and same-named regional
configuration.

LangGraph uses a separate, short-lived autocommit PostgresSaver connection.
Each Agent runtime checkpoint request binds its authenticated Investigation's
tenant and region as session settings on that one connection, then closes it.
The three saver data tables carry non-null namespace columns and forced RLS;
`icheck-checkpoint-schema-prepare` installs their policy under a separate owner
role, and production startup checks the exact policy expression. The runtime
role cannot own those tables or inherit owner privileges and must not have
`TRUNCATE`, which RLS does not govern. See [Agent runtime](agent-runtime.md)
for owner migration and acceptance limits.

Tenant, region, and principal registry models are deliberately exempt from the
generic ORM predicate. Their service methods use explicit tenant relationships
and platform/tenant administration permissions.

## Provisioning and regional defaults

`POST /api/v1/tenancy/tenants` is a platform-admin operation. It creates the
tenant and its default region atomically. A platform admin can then issue the
first tenant-admin token through
`POST /api/v1/tenancy/tenants/{tenant_id}/admins`.

`POST /api/v1/tenancy/regions` creates another region in the caller's tenant.
The creator receives the regional admin binding. The transaction also creates
independent regional defaults for:

- Alert rules;
- change-risk policies;
- the default Agent profile; and
- built-in Agent Tool registrations.

Configuration and Worker natural keys are namespace-local. For example, two
regions may each have an `alerts.list_open` Tool or a `primary` collector
worker without sharing the same database row.

The administration UI is `/settings/tenancy`. Its region switch changes the
active request boundary; it does not copy data between regions.

## Worker pinning

Collectors and the Agent, knowledge-projection, service-indicator, ecosystem
transport, and scaling workers require both:

```text
ICHECK_TENANT_ID=<tenant UUID>
ICHECK_REGION_ID=<region UUID>
```

The IDs are canonicalized, checked against enabled registry rows, stored in the
database session, and never changed by a claimed job. Collector control-plane
requests include the same selectors in their headers, including initial
registration. A bootstrap registration token can therefore create identity in
the selected namespace and must be held as tightly as any workload bootstrap
credential.

Run separate worker processes for separate regions. Do not build a privileged
“all regions” worker loop.

## PostgreSQL roles

The production API and Worker database roles must not own namespace-protected
tables and must not have `BYPASSRLS`. Table ownership and schema migration
belong to a separate migration role. Otherwise PostgreSQL table-owner behavior
could bypass a defense layer even though application predicates still exist.

Recommended separation:

```text
icheck_migrate  owns schema and runs Alembic
icheck_api      non-owner, no BYPASSRLS
icheck_worker   non-owner, no BYPASSRLS
```

Each deployed Worker role should additionally receive only the table
permissions needed by that Worker class. RLS supplements RBAC and least
privilege; it does not replace either.

## Remaining production gates

- mTLS or workload-federated identity and certificate rotation for distributed
  Workers;
- enterprise OIDC or trusted-proxy federation for browser users;
- PostgreSQL multi-region failure, backup/restore, and performance acceptance;
- a tightly governed platform-administration plane for tenant lifecycle
  disablement and recovery.

The current implementation provides application and PostgreSQL namespace
isolation. It does not claim cryptographic Worker identity or geographically
independent database control planes.
