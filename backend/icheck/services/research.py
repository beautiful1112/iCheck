"""Search and read public references; never execute website instructions."""
from datetime import UTC, datetime
import hashlib
from html.parser import HTMLParser
import json
import os
import re
import stat
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

from ..config import get_settings
from ..public_research_http import ResearchUnavailable, fetch, public_url
from ..research_schemas import ResearchDocument, ResearchRead, ResearchResult, ResearchSearch
from .audit import record_audit_event


def now():
    return datetime.now(UTC).isoformat()


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.title_depth = 0
        self.title = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg", "template"}:
            self.hidden += 1
        if tag == "title":
            self.title_depth += 1
        if tag in {"p", "div", "li", "br", "tr", "pre", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "svg", "template"}:
            self.hidden = max(0, self.hidden - 1)
        if tag == "title":
            self.title_depth = max(0, self.title_depth - 1)

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)
            if self.title_depth:
                self.title.append(value)


def plain(value, limit):
    parser = TextExtractor()
    parser.feed(str(value)[:1_000_000])
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()[:limit]


def public_query(value):
    value = " ".join(value.split())
    # OIDs have more than four components and must not be mistaken for IPs.
    if (re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", value)
            or re.search(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[\w.+-]+@[\w.-]+\.[a-z]{2,}", value, re.I)
            or re.search(r"(?:password|passwd|token|secret|community|api[_-]?key)\s*[:=]\s*\S+|-----BEGIN|\bBearer\s+\S+", value, re.I)
            or re.search(r"https?://|\b(?:localhost|[\w.-]+\.(?:local|internal))\b", value, re.I)
            or re.search(r"[\x00-\x1f\x7f]", value)):
        raise ResearchUnavailable("Search public product/technology terms only; omit addresses, credentials and private URLs")
    return value


def status(db=None):
    settings = get_settings()
    from .research_settings import connection
    row = connection(db)
    if row is not None:
        return {"enabled": settings.research_enabled and row.enabled, "provider": row.provider,
                "configured": bool(row.encrypted_secret) if row.provider == "brave" else bool(row.searxng_url),
                "availability_tested": row.last_test_status == "passed", "public_references_only": True,
                "best_effort": False}
    configured = (settings.research_provider == "bing_rss"
                  or settings.research_provider == "brave" and bool(settings.research_api_key_file)
                  or settings.research_provider == "searxng" and bool(settings.research_searxng_url))
    return {"enabled": settings.research_enabled, "provider": settings.research_provider,
            "configured": bool(configured), "availability_tested": False,
            "public_references_only": True,
            "best_effort": settings.research_provider == "bing_rss"}


def _key(path):
    if not path or not os.path.isabs(path):
        raise ResearchUnavailable("Research provider requires a protected API key file")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_uid not in {0, os.geteuid()} or info.st_size > 4096):
                raise ResearchUnavailable("Research API key file permissions are invalid")
            value = handle.read().strip()
        if not value or re.search(r"[\s\x00-\x1f\x7f]", value):
            raise ResearchUnavailable("Research API key file is invalid")
        return value
    except OSError:
        raise ResearchUnavailable("Research API key file is unavailable") from None


def search(payload, *, transport=None, db=None, expected_revision=None):
    payload = ResearchSearch.model_validate(payload)
    settings = get_settings()
    from .research_settings import connection, decrypt, reserve
    row = connection(db)
    provider = row.provider if row else settings.research_provider
    result = ResearchResult(status="unavailable", provider=provider, retrieved_at=now())
    if not settings.research_enabled:
        return result.model_copy(update={"warning": "Internet research is disabled by the operator"}).model_dump()
    if row is not None and not row.enabled:
        return result.model_copy(update={"warning": "Automatic search is disabled in AI Settings → Internet search"}).model_dump()
    if expected_revision is not None and (row is None or row.revision != expected_revision):
        return result.model_copy(update={"warning": "Search settings changed; refresh before testing"}).model_dump()
    if provider == "unconfigured":
        return result.model_copy(update={"warning": "Configure Brave Search or a SearXNG endpoint. Direct public documentation/MIB reads are available; general internet search is not configured."}).model_dump()
    query = public_query(payload.query)
    request = transport or fetch
    try:
        key = None
        if provider == "brave":
            key = decrypt(row) if row else _key(settings.research_api_key_file)
        endpoint = row.searxng_url if row else settings.research_searxng_url
        if row is not None:
            try:
                reserve(db, row)
            except ResearchUnavailable:
                return result.model_copy(update={"warning": "Search request limit reached or settings changed. Review AI Settings → Internet search."}).model_dump()
        if provider == "brave":
            url = "https://api.search.brave.com/res/v1/web/search?" + urlencode({"q": query, "count": payload.limit})
            _, _, body = request(url, timeout=settings.research_timeout_seconds, redirects=0,
                                 headers={"X-Subscription-Token": key})
            document = json.loads(body)
            if not isinstance(document, dict) or ("web" not in document and document.get("type") != "search"):
                raise ResearchUnavailable("Invalid search response")
            entries = document.get("web", {}).get("results", [])
            if not isinstance(entries, list):
                raise ResearchUnavailable("Invalid search results")
            candidates = [(item.get("title", ""), item.get("url", ""), item.get("description", "")) for item in entries[:30]]
        elif provider == "searxng":
            if not endpoint:
                raise ResearchUnavailable("Configure a SearXNG HTTPS search endpoint")
            base = public_url(endpoint)
            if "?" in base:
                raise ResearchUnavailable("SearXNG endpoint must not contain a query")
            _, _, body = request(base + "?" + urlencode({"q": query, "format": "json"}), timeout=settings.research_timeout_seconds)
            entries = json.loads(body).get("results")
            if not isinstance(entries, list):
                raise ResearchUnavailable("Invalid search results")
            candidates = [(item.get("title", ""), item.get("url", ""), item.get("content", "")) for item in entries[:30]]
        else:
            # Keyless fallback, not a contracted search API. Failure is explicit;
            # never replace a failed search with invented search results.
            url = "https://www.bing.com/search?" + urlencode({"q": query, "format": "rss"})
            _, _, body = request(url, timeout=settings.research_timeout_seconds)
            if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
                raise ResearchUnavailable("Research feed contains unsupported XML declarations")
            root = ET.fromstring(body)
            if root.tag != "rss":
                raise ResearchUnavailable("Search provider did not return a search feed")
            candidates = [(item.findtext("title", ""), item.findtext("link", ""), item.findtext("description", ""))
                          for item in root.findall("./channel/item")[:30]]
        sources, seen = [], set()
        query_terms = {word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", query)
                       if word.lower() not in {"official", "documentation", "docs", "site", "com", "org"}}
        for title, url, excerpt in candidates:
            if key and key in str((title, url, excerpt)):
                continue  # Never reflect a provider's copy of our authentication key.
            try:
                url = public_url(url)
            except ResearchUnavailable:
                continue
            if url in seen:
                continue
            if provider == "bing_rss":
                # The public feed sometimes returns unrelated cached results.
                # Reject them instead of presenting irrelevant text as research.
                text = (plain(title, 250) + " " + plain(excerpt, 1500) + " " + url).lower()
                if query_terms and sum(term in text for term in query_terms) < min(2, len(query_terms)):
                    continue
            seen.add(url)
            sources.append({"title": plain(title, 250), "url": url, "excerpt": plain(excerpt, 1500)})
            if len(sources) == payload.limit:
                break
        return ResearchResult(status="ok" if sources else "no_results", provider=provider,
                              sources=sources, retrieved_at=now()).model_dump()
    except (ResearchUnavailable, ValueError, TypeError, AttributeError, ET.ParseError):
        return result.model_copy(update={"warning": "Internet search is unavailable. Check the research provider; no facts were inferred."}).model_dump()


def read(payload, *, transport=None):
    payload = ResearchRead.model_validate(payload)
    if not get_settings().research_enabled:
        raise ResearchUnavailable("Internet research is disabled by the operator")
    url, content_type, body = (transport or fetch)(public_url(payload.url), timeout=get_settings().research_timeout_seconds)
    raw = body.decode("utf-8", "replace")
    if content_type in {"text/html", "application/xhtml+xml"}:
        parser = TextExtractor(); parser.feed(raw)
        title = " ".join(parser.title).strip()[:250]
        text = "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())
    else:
        title, text = "", raw
    return ResearchDocument(url=url, title=title, text=text[:24000], sha256=hashlib.sha256(body).hexdigest(),
                            retrieved_at=now(), truncated=len(text) > 24000).model_dump()


def tools_for_ai(name, db, arguments, principal):
    if "*" not in principal.permissions and "investigations.read" not in principal.permissions:
        raise PermissionError("Internet research requires investigations.read")
    if name not in {"research.search", "research.read"}:
        raise ValueError("Unknown research tool")
    result = search(arguments, db=db) if name == "research.search" else read(arguments)
    # Existing investigation ToolCall retains the exact bounded references.
    # Audit metadata contains neither the query nor fetched body.
    record_audit_event(db, event_type="research.public_reference.read", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="research", entity_id=principal.principal_id or "public-documents",
        details={"tool": name, "status": result.get("status", "ok"), "provider": result.get("provider", "public_https")})
    db.commit()
    return result, []
