# Release scope and remaining work

The 0.1.0-preview.r19.28 distribution delivers N1–N3 with a native, one-command
installer for fresh Ubuntu 24.04 x86_64 hosts. Its database migration head is
`h1n3q5s7u9w2`. No Docker runtime is required.
Publication excludes private host material, uses English documentation, requires
explicit monitoring CIDRs and creates an administrator with an operator-chosen
passphrase. Publishing does not upgrade a running installation.

The exact installer artifact, fresh-host checks and reboot verification are
recorded in the native installer acceptance asset on the GitHub prerelease.
This qualification is separate from the source/application
publication checks; it does not qualify upgrades or other Linux distributions.

Implemented: password login, monitoring adapters, managed credentials, IP/MAC and
supported wireless observations, categorized Studio/monitoring, multi-tool MCP
packages, workflows, bounded investigations, Grafana AI, Alertmanager and
multi-provider settings. Alert investigation is opt-in; silence/closure stops
work at execution boundaries. Brave/SearXNG research needs owner configuration.

Remaining qualification and limits:

- Other Linux distributions, ARM, offline installation and automated upgrades.
- Representative device interoperability, notification delivery and fleet load tests.
- Live Zabbix/Orion interoperability. SolarWinds SaaS, non-node entities and
  cumulative Orion alerts are outside the initial adapter scope.
- CMDB federation such as NetBox remains future work.
- Account/model-specific paid inference qualification.
- End-to-end acceptance of research → monitoring extension → verified dashboard.
- No claim of arbitrary unattended installation or infrastructure remediation.
- No native guided Azure, Bedrock or Vertex authentication.
- Expanded Advanced settings may overflow narrow phone screens with long values.

See [application publication checks](../acceptance/public-preview-qualification.json),
[limitations](engineering-preview-known-limitations.md) and
[architecture](mvp-architecture.md). Private receipts and saved test configuration
are intentionally excluded.

## N1–N3 delivered scope

- N1: read-only Zabbix 7.0/7.4, SolarWinds Platform/Orion SWIS v3 and a versioned
  connector bridge. GUI setup includes source groups, bounded inventory sync,
  optional schedules, reviewed asset mapping, alert feeds and source-attributed
  metric/history tools. Imported inventory does not enable duplicate polling.
- External alert investigation is opt-in. Source suppression/recovery and local
  silence/closure stop further steps; an in-flight call may finish.
  Acknowledgement alone does not stop investigation.
- N2: portable workflows, Skills, tools, collectors, MCP packages and connector
  requirements with local binding review, dependencies, hashes, signature policy
  and import receipts. Importing does not install, execute or schedule them.
- N3: six built-in packages for external monitoring, network diagnostics,
  HTTP/API checks and protected configuration backups. The network package
  includes Cisco IOS, NX-OS and Junos MCP servers, each containing two tools.
- The installer provisions two dedicated integration workers and a shared,
  initially empty source-origin policy. No source or paid provider is activated.

See the [integration and package guide](integrations-and-operation-packages.md).
