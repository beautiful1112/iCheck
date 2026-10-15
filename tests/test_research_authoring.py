from icheck.config import get_settings
from icheck.services import research_authoring


def test_public_terms_do_not_forward_brief_or_internal_device_data():
    query = research_authoring.public_terms({"brief": "Cisco switch private-core-01 at 198.18.0.123 password=hidden needs ARP and MAC tables"})
    assert query == "Cisco ARP MAC official documentation"
    assert "private" not in query and "192.168" not in query and "hidden" not in query


def test_missing_references_search_then_read_before_authoring(monkeypatch):
    monkeypatch.setattr(research_authoring, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    calls = []
    def search(payload):
        calls.append(("search", payload))
        return {"status": "ok", "sources": [{"title": "Cisco", "url": "https://www.cisco.com/docs", "excerpt": "Reference"}]}
    def read(payload):
        calls.append(("read", payload))
        return {"url": payload["url"], "text": "Documented OIDs", "sha256": "a"*64, "truncated": False}
    monkeypatch.setattr(research_authoring.research, "search", search)
    monkeypatch.setattr(research_authoring.research, "read", read)
    evidence = research_authoring.references({"brief": "Cisco SNMP ARP tables"})
    assert [call[0] for call in calls] == ["search", "read"]
    assert evidence["documents"][0]["text"] == "Documented OIDs"


def test_provided_reference_is_reused_without_unnecessary_search(monkeypatch):
    monkeypatch.setattr(research_authoring, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    monkeypatch.setattr(research_authoring.research, "search", lambda *_: (_ for _ in ()).throw(AssertionError("network")))
    assert research_authoring.references({"brief": "Cisco SNMP", "source_document_context": "Provided specification"})["status"] == "provided_reference"


def test_unknown_topic_requests_public_query_instead_of_leaking_arbitrary_brief(monkeypatch):
    monkeypatch.setattr(research_authoring, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    result = research_authoring.references({"brief": "private-customer-x financial account secret internal"})
    assert result["status"] == "needs_public_query" and result["sources"] == []
