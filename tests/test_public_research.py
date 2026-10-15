from dataclasses import replace
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import AgentToolRegistration, AuditEvent, Investigation
from icheck.public_research_http import ResearchUnavailable, public_addresses, public_url
from icheck.research_tools import RESEARCH_TOOLS
from icheck.schema_validation import validate_instance
from icheck.services import research
from icheck.services.agent_authorization import require_tool_permissions, tool_scope_allows
from icheck.services.control_plane_auth import development_principal


@pytest.fixture
def enabled(monkeypatch):
    settings = get_settings().model_copy(update={"research_enabled": True, "research_provider": "bing_rss"})
    monkeypatch.setattr(research, "get_settings", lambda: settings)
    return settings


def rss(*args, **kwargs):
    return args[0], "application/rss+xml", b'''<rss><channel>
      <item><title>Cisco MAC discovery</title><link>https://www.cisco.com/docs/mac.html</link><description>BRIDGE-MIB and IF-MIB</description></item>
      <item><title>Unsafe</title><link>http://127.0.0.1/secret</link></item>
      <item><title>Duplicate</title><link>https://www.cisco.com/docs/mac.html</link></item>
    </channel></rss>'''


def test_search_real_results_are_bounded_citable_and_untrusted(enabled):
    result = research.search({"query": "Cisco ARP MAC SNMP documentation", "limit": 3}, transport=rss)
    assert result["status"] == "ok" and len(result["sources"]) == 1
    assert result["sources"][0]["url"] == "https://www.cisco.com/docs/mac.html"
    assert result["untrusted_reference_material"] and not result["device_support_verified"]
    validate_instance(result, RESEARCH_TOOLS[0]["output_schema"], "research result")


@pytest.mark.parametrize("value", ["http://www.cisco.com/", "https://127.0.0.1/", "https://169.254.169.254/",
    "https://example.local/", "https://user:password@www.cisco.com/", "https://www.cisco.com:8443/",
    "https://www.cisco.com/?token=private", "https://www.cisco.com/\\@127.0.0.1/", "file:///etc/passwd"])
def test_private_or_credentialed_urls_denied(value):
    with pytest.raises(ResearchUnavailable): public_url(value)


@pytest.mark.parametrize("value", ["Cisco 198.18.0.123", "MAC aa:bb:cc:dd:ee:ff", "user@example.com Cisco",
    "community=private Cisco", "password: dontsend Cisco", "https://internal.example.com/config", "switch.internal status"])
def test_private_search_terms_never_leave_server(enabled, value):
    with pytest.raises(ResearchUnavailable):
        research.search({"query": value}, transport=lambda *a, **k: pytest.fail("network called"))


def test_oid_is_a_valid_public_query():
    assert research.public_query("Cisco 1.3.6.1.2.1.4.22.1.2") == "Cisco 1.3.6.1.2.1.4.22.1.2"


def test_dns_mixed_public_private_denied(monkeypatch):
    monkeypatch.setattr("icheck.public_research_http.socket.getaddrinfo", lambda *a, **k:
        [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ResearchUnavailable): public_addresses("docs.example.com")


def test_document_strips_executable_markup_and_retains_hash(enabled):
    document = b"<html><title>Reference</title><script>leak-secret()</script><p>SNMP leaf</p></html>"
    result = research.read({"url": "https://www.cisco.com/docs"}, transport=lambda *a, **k: (a[0], "text/html", document))
    assert "SNMP leaf" in result["text"] and "leak-secret" not in result["text"]
    assert len(result["sha256"]) == 64 and result["title"] == "Reference"
    validate_instance(result, RESEARCH_TOOLS[1]["output_schema"], "research document")


def test_no_invented_sources_on_provider_failure(enabled):
    result = research.search({"query": "Cisco ARP MIB"}, transport=lambda *a, **k: (a[0], "text/html", b"captcha"))
    assert result["status"] == "unavailable" and result["sources"] == []


def test_entity_feed_rejected(enabled):
    result = research.search({"query": "Cisco ARP MIB"}, transport=lambda *a, **k:
        (a[0], "application/xml", b'<!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss>&x;</rss>'))
    assert result["status"] == "unavailable"


def test_disabled_research_does_no_network(monkeypatch):
    monkeypatch.setattr(research, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": False}))
    result = research.search({"query": "Cisco ARP MIB"}, transport=lambda *a, **k: pytest.fail("network called"))
    assert result["status"] == "unavailable"


def test_brave_and_searxng_use_same_result_contract(enabled, monkeypatch, tmp_path):
    key = tmp_path / "key"; key.write_text("research-test-key"); key.chmod(0o600)
    calls = []
    def brave(url, **kwargs):
        calls.append((url, kwargs))
        return url, "application/json", json.dumps({"web": {"results": [{"title": "RFC", "url": "https://www.rfc-editor.org/rfc/rfc4293", "description": "IP-MIB"}]}}).encode()
    monkeypatch.setattr(research, "get_settings", lambda: enabled.model_copy(update={"research_provider": "brave", "research_api_key_file": str(key)}))
    assert research.search({"query": "IP-MIB"}, transport=brave)["status"] == "ok"
    assert calls[0][1]["redirects"] == 0 and calls[0][1]["headers"]["X-Subscription-Token"] == "research-test-key"
    monkeypatch.setattr(research, "get_settings", lambda: enabled.model_copy(update={"research_provider": "searxng", "research_searxng_url": "https://search.example.com/search"}))
    result = research.search({"query": "IP-MIB"}, transport=lambda url, **kw: (url, "application/json", b'{"results":[]}'))
    assert result["status"] == "no_results"


def test_api_and_audit_do_not_include_query_or_source_body(client, enabled, monkeypatch):
    monkeypatch.setattr(research, "fetch", rss)
    response = client.post("/api/v1/research/search", json={"query": "Cisco ARP MIB"})
    assert response.status_code == 200 and response.json()["sources"]
    with SessionLocal() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "research.public_reference.read"))
        assert event and "Cisco ARP MIB" not in str(event.details)
    assert client.get("/api/v1/research/status").json()["enabled"]


def test_research_native_contract_cannot_be_replaced():
    inv = Investigation(permission_snapshot=["investigations.read"], authorization_scope={"all": True}, scope={"capability_task": "grafana-dashboard"})
    tool = AgentToolRegistration(**RESEARCH_TOOLS[0])
    assert tool_scope_allows(inv, tool)
    require_tool_permissions(inv, tool)
    tool.read_only = False
    with pytest.raises(PermissionError): require_tool_permissions(inv, tool)
    tool.read_only = True; tool.handler = "metrics.query_instant"
    with pytest.raises(PermissionError): require_tool_permissions(inv, tool)


def test_source_read_requires_permission(enabled):
    principal = replace(development_principal(), permissions=frozenset({"assets.read"}))
    with pytest.raises(PermissionError): research.tools_for_ai("research.read", None, {}, principal)
