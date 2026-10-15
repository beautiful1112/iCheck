"""Grafana acceptance against actual Prometheus samples (read-only by default).

--exercise-plugin-changes explicitly creates new qualification resources and
tests confirmed revisions/restoration. It never edits seeded or user dashboards.

Optional ephemeral browser state contains human session cookies only, never a
service token or password. Delete it and log out the test session after use.
"""
import argparse
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import ssl
import stat
import time
from uuid import uuid4
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, ProxyHandler, Request, build_opener


def credential(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("Private operator credential ownership/mode required")
        raw = handle.read(4097)
    if len(raw) > 4096:
        raise ValueError("Credential file too large")
    data = json.loads(raw)
    if not isinstance(data.get("username"), str) or not isinstance(data.get("password"), str):
        raise ValueError("Username/password custody is incomplete")
    return data


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(opener, url, *, data=None, method=None, headers=None, expect_json=True):
    with opener.open(Request(url, method=method, headers={"Content-Type": "application/json", **(headers or {})},
                             data=None if data is None else json.dumps(data).encode()), timeout=30) as response:
        raw = response.read(2 * 1024 * 1024)
        return json.loads(raw) if raw and expect_json else None


def logout(opener, base):
    try:
        request(opener, base + "/logout", expect_json=False)
    except HTTPError as error:
        location = urlsplit(error.headers.get("Location", ""))
        origin = urlsplit(base)
        valid = error.code in (302, 303) and location.path.startswith("/grafana/") and (
            not location.netloc or (location.netloc == origin.netloc and location.scheme == "https"))
        error.close()
        assert valid


def exercise_plugin(opener, origin, connection_id, csrf):
    """Explicit qualification writes: new owned resources, never seeded dashboards."""
    api = origin + "/api/v1/grafana"
    headers = {"X-Icheck-CSRF-Token": csrf, "Origin": origin}
    def post(path, body):
        return request(opener, api + path, data=body, headers=headers)
    def apply(plan):
        result = post("/changes/" + plan["id"] + "/confirm", {"expected_plan_hash": plan["plan_hash"], "confirm": True})
        if result["status"] != "applied":
            raise ValueError("Inspect the retained qualification proposal; no write will be replayed")
        return result
    connection = next(row for row in request(opener, api + "/connections") if row["id"] == connection_id)
    assert connection["enabled"]
    names = request(opener, api + "/connections/" + connection_id + "/metrics?filter=up")["metrics"]
    assert "up" in names
    preview_path = "/connections/" + connection_id + "/preview"
    suffix = uuid4().hex[:12]
    folder = apply(post(preview_path, {"resource_kind": "folder", "definition": {"title": "iCheck plugin qualification " + suffix}}))
    definition = {"title": "iCheck actual scrape state " + suffix, "schemaVersion": 41,
        "time": {"from": "now-1h", "to": "now"},
        "templating": {"list": [{"name": "instance", "type": "query", "query": "label_values(up, instance)", "includeAll": True, "multi": True, "allValue": ".*"}]},
        "panels": [{"id": 1, "title": "Actual platform scrape state (not device health)", "type": "timeseries",
            "targets": [{"refId": "A", "expr": 'up{instance=~"$instance"}', "range": True}],
            "gridPos": {"x": 0, "y": 0, "w": 24, "h": 8}}]}
    first = apply(post(preview_path, {"folder_uid": folder["resource_uid"], "definition": definition}))
    definition["title"] += " revised"
    definition["panels"][0]["type"] = "stat"
    second = apply(post(preview_path, {"resource_uid": first["resource_uid"], "folder_uid": folder["resource_uid"],
        "expected_resource_version": first["applied_resource"]["metadata"]["resourceVersion"], "definition": definition}))
    restored = apply(post("/changes/" + second["id"] + "/restore-preview", {}))
    assert restored["definition"] == first["definition"]
    assert restored["applied_resource"]["spec"]["panels"][0]["type"] == "timeseries"
    return {"passed": True, "source": "explicit operator API qualification, not model-generated content",
        "connection_id": connection_id, "folder_uid": folder["resource_uid"], "dashboard_uid": first["resource_uid"],
        "create_change_id": first["id"], "revision_change_id": second["id"], "restore_change_id": restored["id"],
        "retained_previous_definition": second["previous_resource"] is not None,
        "restored_original_panels_and_variables": True, "saved_url": restored["resource_url"],
        "seeded_dashboards_changed": False, "device_or_collection_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--credential-file", required=True, type=Path)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--browser-state-file", type=Path)
    parser.add_argument("--icheck-credential-file", type=Path)
    parser.add_argument("--plugin-connection-id")
    parser.add_argument("--exercise-plugin-changes", action="store_true",
        help="Explicitly create new qualification folder/dashboard, revise and restore; retain history")
    args = parser.parse_args()
    if args.exercise_plugin_changes and (not args.plugin_connection_id or not args.icheck_credential_file):
        parser.error("Qualification writes require --plugin-connection-id and --icheck-credential-file")
    try:
        url = urlsplit(args.url)
        if (url.scheme != "https" or not url.hostname or url.username or url.password or
                url.path.rstrip("/") != "/grafana" or url.query or url.fragment or
                any(ord(char) < 33 or ord(char) == 127 for char in args.url)):
            raise ValueError("Verified credential-free HTTPS Grafana URL required")
        base = args.url.rstrip("/")
        origin = url.scheme + "://" + url.netloc
        jar = CookieJar()
        opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(jar),
                             HTTPSHandler(context=ssl.create_default_context(cafile=args.ca_file)))
        health = request(opener, base + "/api/health")
        try:
            request(opener, base + "/apis/dashboard.grafana.app/v1/namespaces/default/dashboards")
        except HTTPError as error:
            denied = error.code in (401, 403)
            error.close()
            assert denied
        else:
            raise ValueError("Anonymous dashboard API access accepted")
        user = credential(args.credential_file)
        request(opener, base + "/login", data={"user": user["username"], "password": user["password"]},
                headers={"Origin": origin})
        session = next(cookie for cookie in jar if cookie.name == "grafana_session")
        assert session.secure and "HttpOnly" in session._rest
        assert session._rest.get("SameSite", "").lower() == "strict"
        datasource = request(opener, base + "/api/datasources/uid/icheck-prometheus/health")
        assert health["database"] == "ok" and datasource["status"] == "OK"
        dashboards = [request(opener, base + "/apis/dashboard.grafana.app/v1/namespaces/default/dashboards/" + uid)
                      for uid in ("icheck-collection", "icheck-network")]
        now = time.time()
        body = {"from": str(int((now - 300) * 1000)), "to": str(int(now * 1000)),
                "queries": [{"refId": "A", "datasource": {"uid": "icheck-prometheus", "type": "prometheus"},
                             "expr": "up", "range": True, "intervalMs": 30000, "maxDataPoints": 20}]}
        data = request(opener, base + "/api/ds/query", data=body)
        frames = data["results"]["A"]["frames"]
        assert frames and all(frame["data"]["values"][0] for frame in frames)
        latest = max(frame["data"]["values"][0][-1] for frame in frames) / 1000
        assert now - 120 <= latest <= now + 5
        summary = {"passed": True, "grafana_version": health["version"], "anonymous_dashboard_api_denied": True,
                   "username_password_session": True, "secure_httponly_samesite_strict_cookie": True,
                   "datasource_health": datasource["status"],
                   "dashboards": [{"uid": x["metadata"]["name"], "resource_version": x["metadata"]["resourceVersion"]}
                                  for x in dashboards],
                   "actual_metric_frames": len(frames), "latest_sample_age_seconds": round(now - latest, 1),
                   "sample_source": "existing Prometheus/exporter jobs, not a fixture or device probe"}
        if args.icheck_credential_file:
            icheck = credential(args.icheck_credential_file)
            login = request(opener, origin + "/api/v1/auth/login",
                            data={"username": icheck["username"], "password": icheck["password"]},
                            headers={"Origin": origin})
            summary["icheck_login_verified"] = login["principal"]["subject"] == icheck["username"]
            if args.exercise_plugin_changes:
                summary["native_plugin"] = exercise_plugin(opener, origin, args.plugin_connection_id, login["csrf_token"])
        if args.browser_state_file:
            parent = args.browser_state_file.parent.stat()
            assert parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700
            cookies = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path,
                        "expires": c.expires or -1, "httpOnly": "HttpOnly" in c._rest,
                        "secure": c.secure, "sameSite": (c._rest.get("SameSite") or "Strict").capitalize()}
                       for c in jar]
            fd = os.open(args.browser_state_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump({"cookies": cookies, "origins": []}, handle)
            summary["ephemeral_browser_state"] = str(args.browser_state_file)
        else:
            logout(opener, base)
            if args.icheck_credential_file:
                request(opener, origin + "/api/v1/auth/browser-sessions/current", method="DELETE",
                        headers={"X-Icheck-CSRF-Token": login["csrf_token"]})
        print(json.dumps(summary))
        return 0
    except Exception as error:
        print(json.dumps({"passed": False, "error_type": type(error).__name__,
                          "diagnostic": "Check protected custody, TLS, authentication and datasource; secret details withheld"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
