# iCheck engineering preview development goal

Updated 12 October 2026. Use the text below as the replacement development goal.
It supersedes earlier priorities for custom monitoring visualizations, Service
Intelligence, and production qualification before an engineer can try the product.

Clarified 13 October 2026: in-product extensibility includes generating an
executable MCP server and installing/registering it through Studio. A generated
tool contract or a connection to an externally developed server does not meet
that outcome. Monitoring also needs a categorized overview of all configured
device and service targets, with an accessible Alertmanager management section.

Clarified 14 October 2026: Studio starts with a categorized capability library,
not a page containing every conversation. One MCP server package contains its
tools; tools are not separate servers. Keep unvalidated attempts in draft/history
views, and show installation state independently from generation or validation.

## Goal

Deliver a usable, native single-server engineering preview of iCheck for network,
system, and DevOps engineers. iCheck is an AI operations agent that manages
monitoring, investigates faults, and helps users build and improve operational
capabilities through conversation. Prometheus collects and stores time-series
metrics through exporters and adapters. Grafana presents all monitoring metrics.
iCheck must not build its own competing charting or metric dashboard framework.

Build on the existing AI Operator, LangGraph runtime, device onboarding,
credentials, inventory, alerts, and collector infrastructure. Preserve existing
devices, settings, credentials, approved collection boundaries, and history.
Deliver working engineer workflows before adding more platform machinery.

## Required outcomes

1. **Deploy and connect Grafana first.** Install a dedicated Grafana OSS instance
   on this server as a native systemd service, without requiring Docker. Connect
   it to the existing Prometheus instance; do not replace the TSDB or duplicate
   collection jobs. Provide protected browser access, a durable data directory,
   and dashboards showing actual collected data. Keep Prometheus and exporter
   listeners private. Document access, startup, backup, and uninstall boundaries.

2. **Make Grafana manageable through AI.** Implement a Grafana plugin using its
   HTTP APIs behind iCheck's existing typed Tool Registry. The AI can discover
   metrics, find and open dashboards, generate dashboard definitions, and propose
   creation or revision of dashboards, panels, variables, and folders. Validate
   queries and apply changes after a clear preview and user confirmation. Return
   the real saved dashboard URL and retain the previous version for rollback.
   Start with the native adapter; a separate Grafana MCP server is optional,
   not a prerequisite or a second required implementation.

3. **Make navigation fast and understandable.** Keep AI Operator as the home
   page. Add a Dashboards entry opening Grafana and contextual dashboard links
   from devices, alerts, and AI answers, carrying the device and time range.
   Use authenticated full-page links first, not an iframe or custom renderer.
   Keep inventory, IP/MAC histories, Wi-Fi terminals, and settings on supporting
   pages. Remove Services and Service Intelligence from navigation and supported
   product journeys; retire their routes without deleting historical data or
   breaking unrelated alert and investigation functions. Replace legacy metric
   visualization entry points with Grafana links.

   Add a **Monitoring** page for all configured targets, grouped by network,
   Linux, Windows, HTTP/API services, containers and VMware, with an extensible
   category for future plugins. Show enabled, pending, disabled and failing
   targets, collection method, last scrape, freshness of requested measurements,
   associated alerts and Grafana links. Device inventory and the Grafana chart
   overview do not replace this page. Service targets here mean monitored
   endpoints; this does not restore the retired Service Intelligence subsystem.

4. **Redesign Capability Studio around the engineer's task.** Retain the name
   Capability Studio and open with a categorized capability library. Keep the
   conversation builder, saved sessions, version history and server setup on
   separate pages, with a guided sequence: describe, preview, test, enable.
   Offer understandable starting actions such as Monitor a device or API, Build
   a dashboard, and Automate a check. Infer the artifact type where possible.
   Hide schemas, generated code, permissions, dependencies, and deployment
   internals under Advanced details. Show the target, collection interval,
   credential reference, expected metrics, result, and next action in plain
   language. Editing and rollback must work without an external IDE.

5. **Complete conversational monitoring creation.** A user can describe a target
   and desired metrics, supply a credential through a protected field or select
   an existing reference, review the proposed template, test an explicitly
   selected target, and enable continuous collection. The platform generates
   and validates the necessary exporter or adapter configuration, registers the
   approved target with Prometheus, verifies fresh samples, and creates or binds
   a Grafana dashboard. A published draft, successful ping, or exporter `up`
   alone must not be reported as successful metric collection.

6. **Support multiple monitoring technologies through plugins.** Deliver SNMP
   and HTTP/HTTPS first, then Linux and Windows, then containers and VMware.
   SNMP needs a complete intent-to-OID/profile-to-generator-to-installed-module
   path, using real standard/vendor MIBs and displaying unsupported metrics.
   HTTP supports status, latency, TLS, account/token authentication, and a safely
   parsed curl request; API JSON metrics use an adapter exposing Prometheus
   metrics. Windows uses windows_exporter for routine metrics and WMI/CIM tools
   for bounded queries. Containers and VMware use appropriate exporters or API
   adapters. Prometheus scrapes these endpoints; it does not directly execute
   arbitrary curl, WMI, or model-generated code. Every advertised plugin needs
   one working representative path and an honest support/limitations label.

7. **Keep modules replaceable and extendable inside iCheck.** Collectors,
   monitoring templates, dashboard templates, tools, Skills, and workflows share
   a small versioned capability contract: inputs, outputs, secret references,
   permissions, dependencies, validation, activation, health, and rollback.
   Prefer existing exporters and adapters. Generated extensions must not require
   core edits or a product release for each vendor API. Dashboard templates
   produce Grafana definitions, not React chart components. A plugin need not
   be an MCP server; local adapters and MCP share the same tool boundary.

   Studio must also generate executable extension packages, including MCP
   servers backed by Netmiko. The first example logs into an authorized device,
   reads interface status and retrieves configuration backups. Generate the
   implementation, dependency declaration and typed tools together; validate and
   test them, then install and register the reviewed version from the GUI.
   Users can revise, disable and roll back the extension without an external IDE
   or a core release. Code runs in a bounded native extension process with
   protected credential references, not inside the control-plane process.
   One server package can expose multiple tools and has one installation
   identity across revisions. Reuse existing saved credentials. First-use SSH
   identity confirmation belongs in the GUI, with a visible fingerprint and
   explicit confirmation; repeatedly requesting a full public key in chat is
   not the intended engineer journey. A changed key must require renewed review.
   Configuration changes and restores require approval for the exact target
   action; generating or installing a plugin does not authorize those actions.

8. **Use LangGraph for both fixed flows and investigation loops.** Known tasks
   use deterministic workflows. Troubleshooting runs a bounded cycle of plan,
   select tool, execute, inspect evidence, and revise until the objective is
   met, user input is required, or time/cost/step limits are reached. Reuse the
   existing durable state and cancellation. Let users author reusable workflows
   and Skills in Studio. Findings should cite observed evidence, distinguish
   unknowns, and link to Grafana. Actions changing monitored infrastructure
   require explicit approval and verification; unrestricted self-modification
   or autonomous remediation is not part of the preview.

   **Approved 14 October: AI owns investigation, not unrestricted change.** Alert
   triggers and conversations share runtime and linked history. Do not require
   users to predefine a troubleshooting workflow or choose each MCP/tool.
   Select checks from intent and evidence. Provide an off-by-default standing
   alert policy for workspace/site groups, duplicate suppression, bounded
   cost/concurrency and maintenance controls. Enforce read-only diagnosis below
   the model. Missing knowledge calls for research; missing capabilities become
   saved Studio briefs for review and installation approval, followed by a
   context-preserving continuation. Offer successful approaches as Skills, not
   silently published changes. Distinguish source delivery, activation and live
   acceptance.

   User decision: silencing or closing an alert stops the automatic investigation
   it triggered. Preserve history, stop subsequent calls, do not automatically
   restart on silence expiry, and do not equate acknowledgement with closure.
   Grafana customization must be directly accessible on `/dashboards`: describe
   a new dashboard or choose an existing dashboard and edit with AI, continue the
   saved conversation, review and confirm. Do not require a Studio detour or JSON.

9. **Preserve alerts and durable inventory.** Retain IP/MAC and Wi-Fi controller
   terminal observations and histories in PostgreSQL. Keep time-series metrics
   in Prometheus. Add one usable threshold-alert flow with AI assistance,
   notification, and a link to the relevant Grafana dashboard and investigation.
   Use Prometheus rules and Alertmanager for metric alerts, while retaining
   iCheck's existing inventory-event alerts. Do not create two evaluators for the
   same metric rule. Alert acknowledgement must not imply fault resolution.

   Expose **Alertmanager** under Monitoring/Alerts, showing connection readiness,
   active notifications, receivers/routes, silences and delivery history. Reuse
   the existing Prometheus rules, Alertmanager service and iCheck inbox; add the
   missing management surface rather than another alert evaluator.

10. **Keep configuration accessible.** Provide clear settings for AI endpoint,
    model, token, and budgets; Prometheus and Grafana connections; credentials;
    and installed plugins. Service tokens stay server-side and never enter
    dashboard URLs, ordinary chat, logs, or browser storage. A single trusted
    engineering-lab workspace is sufficient for the preview. Do not imply that
    Grafana folder permissions or dashboard variables enforce device-level
    isolation over a shared Prometheus data source.

11. **Reduce testing and storage overhead.** Delete demonstrably obsolete and
    duplicate test scripts after checking consumers, especially release-specific
    byte/SHA comparison loops. Keep focused checks for the changed workflow,
    credential handling, authorization, configuration validation, and data
    preservation. Verify downloaded/distributed artifacts once at their trust
    boundary; do not repeatedly hash whole trees or retest unchanged historical
    releases. Keep necessary cryptography. Reuse one small acceptance path per
    supported plugin; do not add a new permanent script for every revision.
    Prune old test outputs only after excluding active installations, rollback
    dependencies, secrets, databases, and operator backups.

## Delivery order and completion

Work in this order: Grafana deployment and real-data dashboard; native AI Grafana
tools and links; simplified Studio and removal of Services; complete SNMP and
HTTP monitoring-template workflows; Linux/Windows and container/VMware plugins;
alerts and reusable troubleshooting/automation; engineer handoff. Build vertical
slices that reuse the same plugin contract rather than seven separate designers.

An early engineer demo is ready when an engineer can sign in, configure AI, add a
device through the web GUI or conversation, enable an SNMP or HTTP template,
open fresh metrics in Grafana, ask AI to change the dashboard and diagnose a
controlled fault, and review the evidence without editing source or server files.
This early demo is not completion of the remaining advertised integrations.

The goal is complete when those journeys plus one representative Linux, Windows,
container, and VMware path work with their limitations documented; one real
metric alert reaches a configured notification destination; one custom API
collector or workflow is created and revised inside iCheck; and the current
preview has installation/access instructions, a short demo guide, known issues,
and a feedback path for engineers. Record what is source-tested, deployed, and
lab-verified separately. Missing lab access blocks only that live qualification,
not unrelated implementation; never substitute a fixture for a real-device claim.

Defer HA, fleet-scale certification, enterprise SSO, a plugin marketplace,
multi-tenant Grafana isolation, a general visual workflow canvas, advanced OAuth
recovery work, and autonomous infrastructure remediation. They are not preview
release gates. Do not expand the goal to finish every historical milestone.
