# Release scope and remaining work

The sanitized 0.1.0-preview.r19.26 distribution uses migration `a4g6i8k0m2p5`.
Publication changes exclude private host material, use English labels, require
explicit monitoring CIDRs and document first-admin setup. Publishing does not
modify a running installation.

Implemented: password login, monitoring adapters, managed credentials, IP/MAC and
supported wireless observations, categorized Studio/monitoring, multi-tool MCP
packages, workflows, bounded investigations, Grafana AI, Alertmanager and
multi-provider settings. Alert investigation is opt-in; silence/closure stops
work at execution boundaries. Brave/SearXNG research needs owner configuration.

Remaining qualification and limits:

- Clean-host installation acceptance of this distribution.
- Representative device interoperability, notification delivery and fleet load tests.
- Account/model-specific paid inference qualification.
- End-to-end acceptance of research → monitoring extension → verified dashboard.
- No claim of arbitrary unattended installation or infrastructure remediation.
- No native guided Azure, Bedrock or Vertex authentication.
- Expanded Advanced settings may overflow narrow phone screens with long values.

See [qualification](../acceptance/public-preview-qualification.json),
[limitations](engineering-preview-known-limitations.md) and
[architecture](mvp-architecture.md). Private receipts and saved test configuration
are intentionally excluded.
