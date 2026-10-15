# Grafana access and native operation

Grafana runs as a separate native service and queries your configured Prometheus
instance. iCheck's AI Operator remains the home page. The package does not ship
a Grafana account, service token, existing dashboards or a development-host URL.

## Browser access and credentials

Publish Grafana behind your reviewed HTTPS ingress, for example at
`https://YOUR_SERVER:8443/grafana/`. Configure its root URL/subpath consistently
with nginx. Do not enable anonymous administrative access.

Provision a unique Grafana administrator password and keep it in a password
manager. It is **not** the iCheck `admin` password. Signing into iCheck does not
automatically sign into Grafana unless shared identity is explicitly configured.
Create a narrowly scoped Grafana service-account token for iCheck's connection
settings. Store it in the protected UI, not in source files or AI chat.

## Native integration

Use the reviewed tools in `deploy/grafana` with their explicit acknowledgement
and input requirements. Read `native_install.py --help` before deployment;
the helper needs an administrator-provided, verified Grafana distribution and
prepared service/storage custody. It is not permission to overwrite an existing
installation. The systemd template and durable configuration/storage layout
are separate from the iCheck application wheel.

Keep the service listener private behind ingress. Ensure nginx's body/proxy/
FastCGI/SCGI/uWSGI temporary directories are owned by its actual runtime user.
A root-run configuration check must not silently change them to another owner;
incorrect ownership can truncate large JavaScript downloads for slow clients.
Validate configuration and required static resources after every ingress change.

In iCheck, open Grafana connection settings and supply your own URL, public URL,
service token, data source and folder. Review the shared-data-set acknowledgement.
Configure Prometheus access separately. Native dashboard tools do not require
a separate Grafana MCP server.

## Dashboard creation and isolation

Use the Dashboards page to create/revise with AI, review a proposal and explicitly
apply it. Confirm the saved URL, time range and fresh data. Missing series are
not zero traffic or healthy devices. Device/dashboard variables are presentation
filters, not series-level access controls. Users with shared data-source access
may query that data; do not assume iCheck object scope automatically applies.

## Verification, backups and removal

Use `deploy/grafana/verify_live.py --help` for a narrow read-only check with your
own protected credential file and CA. Never publish that credential file.
Back up Grafana configuration, secret custody and consistent storage together.
Do not copy a changing SQLite file as though it were a consistent backup. Test
restoration separately. Retain both application and Grafana version history.

For removal, stop/disable only Grafana and remove only its reviewed ingress routes.
Validate and reload ingress without overwriting unrelated configuration. Keep
state, credentials and backups until deletion is explicitly authorized. Do not
remove Prometheus, exporters, iCheck records or shared TLS custody as a side effect.
