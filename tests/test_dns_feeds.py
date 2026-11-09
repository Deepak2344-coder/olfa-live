import json

import pytest
from olfa_core import dnsinfo, feeds, guarded_http
from olfa_core.intel import Intel
from olfa_core.scanner import Scanner


def fake_dns(records, ok_types=None):
    """records: {(name, type): [data...]}; types not in ok_types simulate a resolver failure when ok_types is given."""
    code = {"A": 1, "NS": 2, "MX": 15, "TXT": 16, "AAAA": 28}

    def req(method, url, **kw):
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(url).query)
        name, t = q["name"][0], q["type"][0]
        if ok_types is not None and t not in ok_types:
            return {"status": 500, "body": "", "error": None}
        ans = [{"type": code[t], "data": d} for d in records.get((name, t), [])]
        return {"status": 200, "body": json.dumps({"Status": 0, "Answer": ans} if ans else {"Status": 0}), "error": None}
    return req


BASE = {
    ("shop.example-test.com", "A"): ["203.0.113.7"],
    ("example-test.com", "NS"): ["ns1.newdns-provider.net.", "ns2.newdns-provider.net."],
    ("example-test.com", "MX"): ["10 mail.example-test.com."],
    ("7.113.0.203.origin.asn.cymru.com", "TXT"): ['"64500 | 203.0.113.0/24 | US | arin | 2020-01-01"'],
    ("ASAS64500.asn.cymru.com", "TXT"): [],
    ("AS64500.asn.cymru.com", "TXT"): ['"64500 | US | arin | 2000-01-01 | EXAMPLE-HOST, US"'],
}


def test_dns_lookup_parses_records_and_asn(monkeypatch):
    monkeypatch.setattr(guarded_http, "request", fake_dns(BASE))
    monkeypatch.setattr(dnsinfo.domainage, "lookup", lambda h: {"age_days": 400})
    info = dnsinfo.lookup("shop.example-test.com")
    assert info["status"] == "ok" and info["a"] == ["203.0.113.7"]
    assert info["ns"] == ["ns1.newdns-provider.net", "ns2.newdns-provider.net"]
    assert info["mx"] == ["mail.example-test.com"]
    assert info["asn"]["asn"] == "AS64500" and "EXAMPLE-HOST" in info["asn"]["org"]
    assert dnsinfo.reasons(info, set()) == []


def test_very_new_nameserver_flagged_only_with_real_age(monkeypatch):
    monkeypatch.setattr(guarded_http, "request", fake_dns(BASE))
    monkeypatch.setattr(dnsinfo.domainage, "lookup", lambda h: {"age_days": 5})
    rs = dnsinfo.reasons(dnsinfo.lookup("shop.example-test.com"), set())
    assert [r["code"] for r in rs] == ["new_nameserver"] and rs[0]["source"] == "dns"
    dnsinfo._cache.clear()
    monkeypatch.setattr(dnsinfo.domainage, "lookup", lambda h: {"age_days": None})
    assert dnsinfo.reasons(dnsinfo.lookup("shop.example-test.com"), set()) == []


def test_no_mx_flag_only_on_brand_lookalike_with_real_answer(monkeypatch):
    recs = {k: v for k, v in BASE.items() if k != ("example-test.com", "MX")}
    monkeypatch.setattr(guarded_http, "request", fake_dns(recs))
    monkeypatch.setattr(dnsinfo.domainage, "lookup", lambda h: {"age_days": 400})
    info = dnsinfo.lookup("shop.example-test.com")
    assert dnsinfo.reasons(info, set()) == []                       # not a look-alike
    assert [r["code"] for r in dnsinfo.reasons(info, {"typosquat"})] == ["no_mail_records"]
    # MX lookup failing is "unknown", never "no mail records"
    dnsinfo._cache.clear()
    monkeypatch.setattr(guarded_http, "request", fake_dns(recs, ok_types={"A", "AAAA", "NS", "TXT"}))
    info = dnsinfo.lookup("shop.example-test.com")
    assert info["status"] == "partial" and dnsinfo.reasons(info, {"typosquat"}) == []


def test_dns_unavailable_is_not_run_and_raises_nothing():
    info = dnsinfo.lookup("shop.example-test.com")  # conftest disables the network
    assert info["status"] == "not_run" and dnsinfo.reasons(info, {"typosquat"}) == []


def test_ip_host_skipped():
    assert dnsinfo.lookup("203.0.113.7")["status"] == "n/a"


FEED_TXT = "https://evil-login.example-phish.com/a/b\nhttp://bad.host.test/x\n"


def _feed_req(body, calls):
    def req(method, url, **kw):
        calls.append(url)
        return {"status": 200, "body": body, "error": None}
    return req


def test_openphish_exact_and_host_match(monkeypatch):
    calls = []
    monkeypatch.setattr(guarded_http, "request", _feed_req(FEED_TXT, calls))
    f = feeds.OpenPhishFeed()
    exact = f.lookup("https://evil-login.example-phish.com/a/b/")
    assert exact["matches"][0]["kind"] == "url"
    host = f.lookup("https://evil-login.example-phish.com/other")
    assert host["matches"][0]["kind"] == "host"
    assert f.lookup("https://clean.example.org/")["matches"] == []
    assert len(calls) == 1  # list downloaded once and cached


def test_openphish_popular_host_is_not_host_matched(monkeypatch):
    monkeypatch.setattr(guarded_http, "request", _feed_req("https://github.com/evil/repo\n", []))
    f = feeds.OpenPhishFeed()
    assert f.lookup("https://github.com/other")["matches"] == []
    assert f.lookup("https://github.com/evil/repo")["matches"][0]["kind"] == "url"


def test_feed_unavailable_reports_not_checked():
    out = feeds.check(["https://example-phish.test/"], [feeds.OpenPhishFeed()])
    assert out["status"] == "not_checked" and "not checked" in out["line"] and out["reasons"] == []


def test_check_builds_line_and_reasons(monkeypatch):
    monkeypatch.setattr(guarded_http, "request", _feed_req(FEED_TXT, []))
    out = feeds.check(["https://evil-login.example-phish.com/a/b"], [feeds.OpenPhishFeed()])
    assert out["line"].startswith("Known threat intelligence matches: 1 (OpenPhish)")
    assert out["reasons"][0]["code"] == "threat_feed_match" and out["reasons"][0]["severity"] == "high"
    clean = feeds.check(["https://fine.example.org/"], [feeds.OpenPhishFeed()])
    assert "none found" in clean["line"]


def test_urlhaus_only_with_key_and_never_leaks_key(monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    assert [f.name for f in feeds.default_feeds()] == ["OpenPhish"]
    feeds._default = None
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "secret-key-123")
    assert [f.name for f in feeds.default_feeds()] == ["OpenPhish", "URLhaus"]
    seen = {}

    def req(method, url, **kw):
        seen.update(kw)
        return {"status": 200, "body": json.dumps({"query_status": "ok", "threat": "malware_download", "url_status": "online"}), "error": None}
    monkeypatch.setattr(guarded_http, "request", req)
    out = feeds.UrlhausFeed("secret-key-123").lookup("http://x.test/m.exe")
    assert out["matches"] and seen["headers"] == {"Auth-Key": "secret-key-123"}
    assert "secret-key-123" not in json.dumps(out)


def test_feed_exception_does_not_break_scan_helper():
    class Boom(feeds.Feed):
        name = "Boom"

        def lookup(self, url):
            raise RuntimeError("x")
    assert feeds.check(["http://a.test"], [Boom()])["status"] == "not_checked"


def test_scan_includes_dns_and_threat_intel_and_fuses(monkeypatch, tmp_path):
    from test_core import CLEAN_HTML, serve
    srv, port = serve(CLEAN_HTML)
    url = f"http://localhost:{port}/"
    sc = Scanner(intel=Intel(str(tmp_path / "i.db")), allow_private=True)
    out = sc.scan(url, deep=True)
    assert out["threat_intel"]["status"] == "not_checked" and "Known threat intelligence matches" in out["threat_intel"]["line"]
    assert out["dns"]["status"].startswith("skipped")
    # public mode with mocked DNS and a feed that lists the URL
    sc2 = Scanner(intel=Intel(str(tmp_path / "j.db")), allow_private=False)
    monkeypatch.setattr("olfa_core.scanner.dnsinfo.lookup", lambda h: {"status": "ok", "a": ["203.0.113.7"], "mx_checked": True, "mx": ["m"], "ns_age": {"newns.net": 3}})
    monkeypatch.setattr("olfa_core.scanner.feeds.check", lambda urls, feeds_=None: {
        "status": "ok", "matches": [{"source": "OpenPhish", "kind": "url", "detail": "listed", "url": urls[0]}], "sources": [{"name": "OpenPhish", "status": "ok"}],
        "line": "Known threat intelligence matches: 1 (OpenPhish)",
        "reasons": [__import__("olfa_core.schema", fromlist=["reason"]).reason("threat_feed_match", "listed", "high", {}, "feed")]})
    monkeypatch.setattr("olfa_core.scanner.crawl", lambda u, allow_private=False: {"final_url": "http://listed.example-test.org/", "hops": [{"url": u, "kind": "final"}], "final_page": None, "flags": [], "error": None})
    r = sc2.scan("http://listed.example-test.org/", deep=True)
    codes = {x["code"]: x["source"] for x in r["reasons"]}
    assert codes["threat_feed_match"] == "feed" and codes["new_nameserver"] == "dns"
    assert r["threat_intel"]["line"].endswith("(OpenPhish)") and r["score"] > 0.4
    assert r["dns"]["a"] == ["203.0.113.7"]
