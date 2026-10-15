import pytest
from icheck.services import mib_research
from icheck.config import get_settings
from icheck.public_research_http import ResearchUnavailable


def test_dependency_downloads_have_hashes_and_preserve_supplied_sources(monkeypatch):
    monkeypatch.setattr(mib_research, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    calls = []
    base = 'BASE-MIB DEFINITIONS ::= BEGIN\nEND\n'
    requested = 'VENDOR-MIB DEFINITIONS ::= BEGIN\nIMPORTS thing FROM BASE-MIB;\nEND\n'
    def fetch(url, **kwargs):
        calls.append(url)
        return url, "text/plain", requested.encode()
    bundle = mib_research.complete_bundle(["VENDOR-MIB"], [base], transport=fetch)
    assert len(calls) == 1 and calls[0].endswith("/VENDOR-MIB.my")
    assert bundle["documents"] == [base, requested]
    assert len(bundle["sources"][0]["sha256"]) == 64


@pytest.mark.parametrize("names", [["../secret"], ["http://host/MIB"], [], ["MIB"] * 17])
def test_bad_module_names_do_not_fetch(names):
    with pytest.raises(ValueError):
        mib_research.complete_bundle(names, [], transport=lambda *a, **k: pytest.fail("network"))


def test_offline_complete_bundle_is_usable_without_internet():
    bundle = mib_research.complete_bundle(["BASE-MIB"], ["BASE-MIB DEFINITIONS ::= BEGIN\nEND"],
        transport=lambda *a, **k: pytest.fail("network"))
    assert bundle["sources"] == [] and len(bundle["documents"]) == 1


def test_missing_dependency_cannot_silently_compile_offline():
    with pytest.raises(ValueError, match="Missing MIB"):
        mib_research.complete_bundle(["BASE-MIB"], [], transport=lambda *a, **k: pytest.fail("network"))


def test_import_cycles_terminate_and_description_cannot_add_dependency():
    first = 'A-MIB DEFINITIONS ::= BEGIN\nIMPORTS a FROM B-MIB;\nDESCRIPTION "FROM SECRET-MIB"\nEND'
    second = 'B-MIB DEFINITIONS ::= BEGIN\nIMPORTS b FROM A-MIB;\nEND'
    assert len(mib_research.complete_bundle(["A-MIB"], [first, second])["documents"]) == 2


def test_mismatched_remote_module_denied(monkeypatch):
    monkeypatch.setattr(mib_research, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    with pytest.raises(ValueError, match="requested module"):
        mib_research.complete_bundle(["A-MIB"], [], transport=lambda url, **kw:
            (url, "text/plain", b"B-MIB DEFINITIONS ::= BEGIN\nEND"))


def test_smi_v1_dependency_fallback_is_bounded_and_cited(monkeypatch):
    monkeypatch.setattr(mib_research, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if "/v2/" in url:
            raise ResearchUnavailable("Not found", status_code=404)
        return url, "text/plain", b"TOKEN-RING-RMON-MIB DEFINITIONS ::= BEGIN\nEND"
    bundle = mib_research.complete_bundle(["TOKEN-RING-RMON-MIB"], [], transport=fetch)
    assert len(calls) == 2
    assert calls[0].endswith("/v2/TOKEN-RING-RMON-MIB.my")
    assert calls[1].endswith("/v1/TOKEN-RING-RMON-MIB.my")
    assert bundle["sources"][0]["url"] == calls[1]


def test_legacy_smi_macros_use_versioned_net_snmp_source(monkeypatch):
    monkeypatch.setattr(mib_research, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        return url, "text/plain", b"RFC1155-SMI DEFINITIONS ::= BEGIN\nEND"
    bundle = mib_research.complete_bundle(["RFC1155-SMI"], [], transport=fetch)
    assert calls == ["https://raw.githubusercontent.com/net-snmp/net-snmp/v5.9/mibs/RFC1155-SMI.txt"]
    assert bundle["sources"][0]["url"] == calls[0]


@pytest.mark.parametrize("status", [None, 401, 403, 429, 500])
def test_dependency_does_not_retry_non_404_failures(monkeypatch, status):
    monkeypatch.setattr(mib_research, "get_settings", lambda: get_settings().model_copy(update={"research_enabled": True}))
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        raise ResearchUnavailable("Unavailable", status_code=status)
    with pytest.raises(ResearchUnavailable, match="Public source for MIB"):
        mib_research.complete_bundle(["A-MIB"], [], transport=fetch)
    assert len(calls) == 1
