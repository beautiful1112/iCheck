"""Set a human web password through the API using a protected administrator token.

Passwords are read from a TTY, never command arguments or environment variables.
This helper does not create accounts or change API/collector credentials.
"""
import argparse
import getpass
import json
from pathlib import Path
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

if __package__:
    from .preview_smoke import API, MAX_BODY, SmokeError, api_base, read_token
else:
    from preview_smoke import API, MAX_BODY, SmokeError, api_base, read_token


def set_password(api: API, password: str, principal_id: str | None = None) -> str:
    if not 15 <= len(password) <= 256:
        raise SmokeError("Password must contain 15 to 256 characters")
    if principal_id is None:
        identity = api.get("/auth/me")
        if identity.get("principal_type") != "user" or not identity.get("principal_id"):
            raise SmokeError("A persisted human administrator is required")
        principal_id = identity["principal_id"]
    request = Request(
        api.base + "/auth/principals/" + quote(principal_id, safe="") + "/password",
        method="PUT", headers={"Authorization": "Bearer " + api.token,
                               "Content-Type": "application/json", "Accept": "application/json"},
        data=json.dumps({"password": password, "reason": "Protected operator password provisioning"}).encode(),
    )
    try:
        with api.opener.open(request, timeout=api.timeout) as response:
            body = response.read(MAX_BODY + 1)
            if response.status != 200 or len(body) > MAX_BODY:
                raise SmokeError("Password provisioning returned an invalid response")
            document = json.loads(body)
            if document.get("password_login_configured") is not True or not isinstance(document.get("subject"), str):
                raise SmokeError("Password provisioning was not confirmed")
            return document["subject"]
    except HTTPError as exc:
        code = exc.code
        exc.close()
        raise SmokeError(f"Password provisioning returned HTTP {code}") from None
    except (URLError, OSError, UnicodeError, json.JSONDecodeError):
        raise SmokeError("Password provisioning transport failed; check account state before retrying") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--ca-file")
    parser.add_argument("--principal-id", help="Existing human account; defaults to the token owner")
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty():
            raise SmokeError("A protected interactive terminal is required")
        api = API(api_base(args.api), read_token(args.token_file), ca_file=args.ca_file, timeout=15)
        password = getpass.getpass("New web password (15 to 256 characters): ")
        confirmation = getpass.getpass("Confirm web password: ")
        if password != confirmation:
            raise SmokeError("Passwords do not match")
        username = set_password(api, password, args.principal_id)
        print("Password saved. Web username: " + username)
        print("Existing browser sessions were revoked. API tokens and collector credentials are unchanged.")
        return 0
    except (SmokeError, OSError, ssl.SSLError, EOFError, KeyboardInterrupt):
        print("Password provisioning failed. Check terminal access, password policy, TLS, permissions and account state.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
