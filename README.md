# iCheck

An AI-native IT operations platform built around an operator agent, extensible
capabilities and evidence-based monitoring.

## Engineering Preview 0.1.0 · r19.27

This is a **single-node engineering preview**, not a production-readiness or
large-fleet scalability claim. No operator database, accounts, provider tokens,
enrolled devices, saved SSH credentials or private lab configuration is included.

- **AI Operator:** bounded investigation loops, tool discovery, evidence and follow-up conversations.
- **Capability Studio:** conversational collectors, workflows, Skills, visualizations and multi-tool MCP packages.
- **Monitoring:** devices/services with Prometheus, SNMP, HTTP/API, Linux/Windows, container and VMware adapters.
- **Inventory:** devices, interfaces, IP/MAC and supported wireless terminal observations.
- **Dashboards:** direct AI creation/revision, proposal review and explicit Grafana application.
- **Alerts:** metric rules, Alertmanager and opt-in automatic read-only investigation.
- **AI providers:** OpenRouter, OpenAI, Claude, Gemini, DeepSeek and regional Qwen presets.
- **Internet research:** configurable Brave Search or SearXNG with bounded use.

Draft generation does not prove correctness or authorize installation. Model
calls may incur charges. Infrastructure changes remain separately governed.

## Download and deploy

Download the `.run` installer and `SHA256SUMS` from
[Releases](https://github.com/beautiful1112/iCheck/releases). Verify the checksum,
then run this command on a dedicated fresh Ubuntu 24.04 x86_64 server:

```bash
sudo bash icheck-0.1.0-preview.r19.27-ubuntu24.04-amd64.run
```

The [one-command installation guide](docs/native-one-command-installer.md)
explains prerequisites, prompts, HTTPS, credentials and recovery. The installer
automatically provisions native systemd services without Docker. Its prebuilt
application is embedded; OS and monitoring prerequisites require network access.
It refuses existing installations and is not an unattended upgrade tool.

The earlier r19.26 native archive remains available for administrators following
the [manual installation/upgrade procedure](docs/engineering-preview-installation.md).
Source archives contain reusable code, English documentation and synthetic tests;
GitHub's automatically generated source downloads are not installation packages.

### First login

| Setting | Value |
| --- | --- |
| Web username | `admin`, created by the native installer |
| Web password | The unique 15–256-character passphrase entered during setup |
| Default/shared password | **None** |
| Login page | `https://YOUR_SERVER:8443/login`, or your configured HTTPS origin |

Complete the interactive password step before signing in. Never use `admin` as
a password or publish real credentials. Tokens are for APIs/workers, not normal
web sign-in. Grafana credentials are separate unless shared identity is configured.

## Documentation

- [Installation and upgrade](docs/engineering-preview-installation.md)
- [Account access](docs/engineering-preview-server-access.md)
- [User manual](docs/engineering-preview-quick-start.md)
- [AI providers and Advanced settings](docs/ai-multi-provider-setup.md)
- [Studio](docs/capability-studio.md) and [Agent runtime](docs/agent-runtime.md)
- [Monitoring](docs/continuous-monitoring.md), [Grafana](docs/grafana-monitoring-design.md) and [alerting](docs/metric-alerts.md)
- [Limitations](docs/engineering-preview-known-limitations.md) and [remaining work](docs/development-plan.md)
- [Architecture](docs/mvp-architecture.md) and [design history](iCheck_project_design.md)
- [Native installer acceptance](acceptance/native-installer-r19-27.json)
- [Application publication checks (r19.26)](acceptance/public-preview-qualification.json)

All documentation is English. Historical design notes describe development
decisions, not configuration shipped to new installations.

## Source development

Use Python 3.12 and Node.js 22.13 or newer. Never point tests at a real database.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,windows,extensions]'
.venv/bin/python -m pytest tests deploy/tests
cd frontend
npm run install:ci
node --test tests/*.test.mjs
npm run build:native
```

The Docker files are optional development scaffolding. Environment examples are
templates, not production credentials. Package the GUI using
`npm run package:native -- --out /absolute/new/frontend-directory`; use
`deploy/build_engineering_preview.py --help` for source-verified native packaging.
Keep the selected runtime manifest and wheelhouse together.
See [security and publication](SECURITY.md).
