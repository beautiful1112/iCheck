# First login and account access

The documented bootstrap creates web username **`admin`**. Use `--admin-username`
for another name. `--operator-user` identifies the local Linux user receiving
protected bootstrap-token custody, not the web username.

**There is no default password.** Choose a unique 15–256-character passphrase at
the hidden prompts of `preview_operator_password.py`, then use that value to
sign in. No existing installation's credentials are distributed. Follow the
[installation manual](engineering-preview-installation.md).

Open `https://YOUR_SERVER:8443/login` or your configured HTTPS origin. Verify and
trust the preview CA delivered by your administrator; never blindly trust an
unknown certificate or disable verification.

## Password changes and recovery

Use Account settings to change your password. An authorized administrator can
reset another human account in Identity. Resets revoke browser sessions;
API/collector tokens remain separate. For initial setup or administrative reset:

```bash
python3 "$BUNDLE/tools/preview_operator_password.py" \
  --api https://YOUR_SERVER:8443/api/v1 \
  --token-file /var/lib/icheck-preview-access/admin-access-token \
  --ca-file /var/lib/icheck-preview-access/preview-ca.pem
```

Run as the local operator owning the private token file. Its token must still be
valid and authorized. Enter the password only at hidden prompts, never as a
command argument or environment variable. If it expired and no admin can sign
in, use controlled administrative recovery; do not disable authentication or
insert a shared password. There is no email-based recovery in this preview.

## Grafana and Internet exposure

Grafana browser credentials and its service-account token for iCheck are separate.
Provision and store them on your own host. No Grafana account/token is shipped.
Before Internet exposure, use trusted HTTPS, unique passwords, firewall rules,
restricted administration, backups and independent security review. Keep database,
exporter and worker listeners private. This preview is not a security certification.
