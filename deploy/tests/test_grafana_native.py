"""Focused config/preservation checks for the reusable Grafana installation."""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    path = Path(__file__).resolve().parents[1] / "grafana" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load("native_install")
templates = load("dashboards")
live = load("verify_live")


def test_config_keeps_private_metrics_and_password_file_custody():
    ini = native.grafana_config("https://198.18.0.100:8443/grafana/")
    assert "http_addr = 127.0.0.1" in ini and "http_port = 3001" in ini
    assert "cookie_secure = true" in ini and "cookie_samesite = strict" in ini
    assert "admin_password = $__file{" in ini and "secret_key = $__file{" in ini
    assert "[auth.anonymous]\nenabled = false" in ini
    assert "allow_sign_up = false" in ini and "allow_embedding = false" in ini
    assert "[unified_alerting]\nenabled = false" in ini


@pytest.mark.parametrize("url", [
    "http://example.test/grafana/", "https://user:token@example.test/grafana/",
    "https://example.test/", "https://example.test/grafana/?token=secret",
    "https://example.test/grafana/#secret", "https://example.test/grafana/\n",
])
def test_public_url_cannot_carry_secrets_or_ini_injection(url):
    with pytest.raises(ValueError):
        native.grafana_config(url)


def test_ingress_extension_does_not_replace_frontend_api_or_worker_routes():
    original = "server {\n        location /api/v1/ { proxy_pass http://127.0.0.1:8000; }\n" + (
        "        location / {\n            proxy_pass http://127.0.0.1:3000;\n        }\n}\n"
        "server { listen 127.0.0.1:8444 ssl; ssl_verify_client on; }\n")
    extended = native.ingress_with_grafana(original)
    assert extended.replace(native.GRAFANA_LOCATION, "", 1) == original
    assert "proxy_pass http://127.0.0.1:3001;" in extended
    assert 'proxy_set_header X-WEBAUTH-USER "";' in extended
    assert 'proxy_set_header Upgrade $http_upgrade;' in extended
    assert 'location /grafana/api/live/' in extended
    with pytest.raises(ValueError):
        native.ingress_with_grafana(extended)
    with pytest.raises(ValueError):
        native.ingress_with_grafana("unexpected deployment")


def test_dashboards_use_real_standard_metrics_without_a_second_renderer():
    dashboards = templates.baseline_dashboards(icheck_url="https://icheck.test/")
    assert [x["metadata"]["name"] for x in dashboards] == ["icheck-collection", "icheck-network"]
    for dashboard in dashboards:
        assert dashboard["spec"]["editable"] is True
        assert dashboard["spec"]["links"][0]["url"] == "https://icheck.test/"
        assert "not" in dashboard["spec"]["description"]
        for panel in dashboard["spec"]["panels"]:
            assert panel["datasource"]["uid"] == "icheck-prometheus"
            assert panel["type"] in {"stat", "timeseries"}
            assert panel["fieldConfig"]["defaults"]["noValue"] == "No data"
    network = dashboards[1]["spec"]
    assert "${device:regex}" in network["panels"][1]["targets"][0]["expr"]
    assert "rate(ifHCInOctets" in network["panels"][1]["targets"][0]["expr"]
    assert "timestamp(ifOperStatus" in network["panels"][5]["targets"][0]["expr"]
    assert network["templating"]["list"][0]["name"] == "device"


def test_existing_data_is_not_adopted_by_first_install(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "trusted", lambda _: None)
    for name in ("CONFIG", "DATA", "ACTIVE", "RELEASES", "UNIT", "BACKUP"):
        monkeypatch.setattr(native, name, tmp_path / name.lower())
    native.DATA.mkdir()
    with pytest.raises(ValueError, match="Existing Grafana"):
        native.install(tmp_path / "never-opened.tar.gz", "https://icheck.test/grafana/", "operator")


def test_verifier_keeps_credentials_private_and_rejects_symlinks(tmp_path):
    path = tmp_path / "credential.json"
    path.write_text('{"username":"operator","password":"test-only-value"}')
    path.chmod(0o600)
    assert live.credential(path)["username"] == "operator"
    path.chmod(0o644)
    with pytest.raises(ValueError):
        live.credential(path)
    path.chmod(0o600)
    link = tmp_path / "linked-credential.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        live.credential(link)


def test_verifier_does_not_forward_login_requests_through_redirects():
    assert live.NoRedirect().redirect_request(None, None, 302, None, None, "https://other.test/") is None
