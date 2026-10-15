# Release scope and remaining work

The 0.1.0-preview.r19.27 distribution adds a native, one-command installer for
fresh Ubuntu 24.04 x86_64 hosts. It embeds the unchanged, sanitized r19.26
application and uses migration `a4g6i8k0m2p5`. No Docker runtime is required.
Publication excludes private host material, uses English documentation, requires
explicit monitoring CIDRs and creates an administrator with an operator-chosen
passphrase. Publishing does not upgrade a running installation.

The exact installer artifact, fresh-host checks and reboot verification are
recorded in [native installer acceptance](../acceptance/native-installer-r19-27.json).
This qualification is separate from the earlier r19.26 source/application
publication checks; it does not qualify upgrades or other Linux distributions.

Implemented: password login, monitoring adapters, managed credentials, IP/MAC and
supported wireless observations, categorized Studio/monitoring, multi-tool MCP
packages, workflows, bounded investigations, Grafana AI, Alertmanager and
multi-provider settings. Alert investigation is opt-in; silence/closure stops
work at execution boundaries. Brave/SearXNG research needs owner configuration.

Remaining qualification and limits:

- Other Linux distributions, ARM, offline installation and automated upgrades.
- Representative device interoperability, notification delivery and fleet load tests.
- Account/model-specific paid inference qualification.
- End-to-end acceptance of research → monitoring extension → verified dashboard.
- No claim of arbitrary unattended installation or infrastructure remediation.
- No native guided Azure, Bedrock or Vertex authentication.
- Expanded Advanced settings may overflow narrow phone screens with long values.

See [application publication checks](../acceptance/public-preview-qualification.json),
[limitations](engineering-preview-known-limitations.md) and
[architecture](mvp-architecture.md). Private receipts and saved test configuration
are intentionally excluded.
