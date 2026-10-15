# iCheck user manual

## Sign in and configure AI

Complete the [installation manual](engineering-preview-installation.md). The
initial username is `admin`; use the passphrase entered during setup. **There is
no default password.** See [account access](engineering-preview-server-access.md).

Open AI providers and routing (`/settings/ai`). Create a connection, select a
provider, enter your API key in the protected field and approve its endpoint.
Saving encrypts the key and does not replace existing routes. Verify the key,
discover models, then approve a small inference test. Charges may apply. Assign
the tested model to investigations/dashboard work, Studio authoring, or both.
Replacing routes requires explicit consent.

OpenRouter, OpenAI, Claude, Gemini, DeepSeek and regional Qwen endpoints are
available. API access is separate from chat subscriptions. The
[provider guide](ai-multi-provider-setup.md) explains Advanced settings.
Configure Internet search separately with your own Brave key or SearXNG endpoint
and request budget. No provider, model, token or search endpoint is preconfigured.

## Add devices and services

Use Assets → Add device or Monitoring → Add monitoring. Supply your own address,
type and collection method. Store secrets under Device credentials, not chat.
Select the saved credential for a connection. Approved gateway networks and
collector capabilities must be configured before target tests.

Monitoring represents devices/services. SNMP, SSH, HTTP and exporters are methods
attached to them; on-demand SSH is not a separate continuous monitoring resource.
Test a method, review its result and explicitly enable collection. Verify fresh
expected measurements: a login or `up=1` does not prove every metric exists.
No devices, schedules or lab allowlists are shipped.

## Create capabilities with AI

Studio groups collectors, MCP servers, tools, workflows, Skills and visualizations.
Conversations/history have separate views. Describe the outcome and interface;
provide documentation or use configured research when needed.

An MCP package is **one server containing one or more tools**. Review generated
behavior/permissions, then approve installation. iCheck manages runtime and
registration. Device identity, credentials and scope belong to target readiness
and execution, not repeated per-device server installations. Installation state
is separate from draft state. Optional live tests require approval.

Adapter/runtime boundaries still apply: arbitrary generated software is not
automatically safe or supported. A backup tool is not restoration/remediation.
Review supported operations before approving a package.

## Customize Grafana with AI

Open Dashboards. Describe a new dashboard in Create a dashboard with AI, or use
an existing dashboard's AI revision action. AI discovers metrics and prepares a
proposal. Review queries, target, time range, refresh and panels; explicitly apply
it to Grafana. Continue revisions in saved conversations. A proposal is not an
installed dashboard: open its saved URL and verify current data. Grafana login
remains separate unless shared identity is configured.

## Alerts and automatic investigation

Configure metric rules after measurements exist. Review thresholds/hold periods.
Inspect Alertmanager readiness, routes and delivery. Supply your own notification
destinations; none are inherited from a development host.

Automatic investigation is **off by default**. AI Settings → Automatic
investigation provides scope, severity, concurrency and daily/budget limits.
AI selects authorized tools without a mandatory workflow. Missing evidence or
capabilities must be reported; installations/infrastructure changes need approval.

Closing or silencing stops automatic investigation at execution boundaries.
An in-flight call may finish. Acknowledgement alone does not stop investigation;
ending silence does not automatically restart an old episode. Closing an alert
does not prove recovery.

## Backups and updates

Back up PostgreSQL, configuration, encryption keys, Grafana storage and monitoring
data. A dump without associated key custody may be unusable. Never commit these
backups. Read [limitations](engineering-preview-known-limitations.md) before upgrading.
