# Security and publication

This preview needs independent review before public or production deployment.
Restrict administration, database, exporter and worker listeners. Use required
authentication, trusted HTTPS and unique credentials. Automatic investigation
stays off until its scope and budget are approved.

The initial username is `admin`; its passphrase is chosen interactively. There
is no shared password. Never commit provider keys, tokens, real credentials,
environment files, database/device backups, private keys, browser state, real
targets or private receipts. Tests/examples are synthetic, not runtime data.

Scan source and built archives. Narrow `gitleaks:allow` comments identify only
synthetic rejection fixtures. Inspect nested wheel/archive contents too.
If a real credential is published, revoke/rotate it first; removing the latest
file does not remove history or downloaded assets. Coordinate history replacement
explicitly; never silently force-push another contributor's work. Report security
issues privately to the repository owner, without live credentials.
