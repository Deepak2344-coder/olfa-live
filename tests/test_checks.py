"""The per-scan "what was checked" panel plus the rules added for it."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from olfa_core import domainage, heuristics, webcheck
from olfa_core.checks import ROWS, build
from olfa_core.scanner import Scanner
from olfa_core.intel import Intel

IDS = [rid for rid, _l, _c in ROWS]


def codes(reasons):
    return {r["code"] for r in reasons}


# ---------- URL length ----------
def test_long_url_thresholds():
    short = heuristics.analyze("http://x.com/login")
    assert "long_url" not in codes(short)
    med = heuristics.analyze("http://x.com/" + "a" * 160)
    assert "long_url" in codes(med)
    assert [r["severity"] for r in med if r["code"] == "long_url"] == ["low"]
    huge = heuristics.analyze("http://x.com/" + "a" * 400)
    assert "long_url" in codes(huge)
    assert [r["severity"] for r in huge if r["code"] == "long_url"] == ["medium"]


# ---------- homoglyphs / punycode ----------
def test_homoglyph_typosquat_detected():
    out = heuristics.analyze("https://xn--pypal-4ve.com/signin")
    hits = [r for r in out if r["code"] in ("typosquat", "brand_impersonation")]
    assert hits, out
    assert hits[0]["details"].get("homoglyph")
    assert hits[0]["severity"] == "high"


def test_real_paypal_still_clean():
    assert not [r for r in heuristics.analyze("https://www.paypal.com/signin")
                if r["code"] in ("typosquat", "brand_impersonation")]


def test_fullwidth_and_zero_width_folded():
    out = heuristics.analyze("http://ｐａｙｐａｌ.com/signin")  # fullwidth latin
    assert any(r["code"] in ("typosquat", "brand_impersonation") for r in out)


# ---------- # / javascript links ----------
def _page(href_list):
    hrefs = "".join(f'<a href="{h}">x</a>' for h in href_list)
    return {"status": 200, "headers": {}, "cookies": [],
            "body": f"<html><body>{hrefs}</body></html>", "error": None}


def test_javascript_link_payload():
    w = webcheck.assess(_page(["#", "javascript:void(0)",
                               "javascript:document.location='http://evil.tld/'"]), "https://a.test/")
    assert "javascript_link_payload" in codes(w["reasons"])


def test_hidden_link_targets_majority():
    hrefs = ["#"] * 6 + ["https://a.test/1", "https://a.test/2"]
    w = webcheck.assess(_page(hrefs), "https://a.test/")
    assert "hidden_link_targets" in codes(w["reasons"])
    assert w["web"]["link_targets"]["stubs"] == 6


def test_normal_links_not_flagged():
    hrefs = [f"https://a.test/{i}" for i in range(10)]
    w = webcheck.assess(_page(hrefs), "https://a.test/")
    assert not {"javascript_link_payload", "hidden_link_targets"} & codes(w["reasons"])


# ---------- domain age ----------
def test_domain_age_reasons():
    assert domainage.reasons({"age_days": None, "error": "rdap_http_404"}) == []
    assert domainage.reasons({"age_days": 4000}) == []
    young = domainage.reasons({"host": "x.test", "registered": "2026-10-01", "age_days": 5})
    assert young[0]["code"] == "new_domain" and young[0]["severity"] == "high"
    mid = domainage.reasons({"host": "x.test", "registered": "2026-06-01", "age_days": 120})
    assert mid[0]["code"] == "new_domain" and mid[0]["severity"] == "medium"


# ---------- panel shape ----------
def _status(**kw):
    s = {"threat": "ok", "web": "ok", "certificate": "ok", "intel": "ok"}
    s.update(kw)
    return s


def test_panel_quick_scan_states():
    from olfa_core.schema import reason
    rs = [reason("brand_impersonation", "m", "high", {}, "threat")]
    panel = {r["id"]: r for r in build(reasons=rs, status=_status(web="skipped (quick scan)",
                                                                 certificate="skipped (quick scan)"),
                                       deep=False)}
    assert set(panel) == set(IDS)  # exactly one row per known check, no 'other'
    assert panel["homoglyph"]["state"] == "fired"
    assert panel["url_length"]["state"] == "clean"
    assert panel["certificate"]["state"] == "not_run"
    assert panel["domain_age"]["state"] == "not_run"
    assert panel["form_actions"]["state"] == "not_run"


def test_panel_http_certificate_not_applicable_and_age_unknown():
    from olfa_core.schema import reason
    rs = [reason("no_https", "m", "medium", {}, "certificate")]
    panel = {r["id"]: r for r in build(reasons=rs, status=_status(certificate="n/a (http)"), deep=True,
                                       domain_age={"age_days": None, "error": "rdap_http_404"})}
    assert panel["certificate"]["state"] == "fired"
    assert panel["domain_age"]["state"] == "unknown"
    assert panel["redirects"]["state"] == "clean"
    assert "other" not in panel


def test_panel_age_note_when_known():
    panel = {r["id"]: r for r in build(reasons=[], status=_status(), deep=True,
                                       domain_age={"age_days": 900, "registered": "2023-01-01"})}
    assert panel["domain_age"]["state"] == "clean"
    assert "2023-01-01" in panel["domain_age"]["note"]


def test_scan_result_contains_checks_panel():
    sc = Scanner(intel=Intel(":memory:"))
    res = sc.scan("https://github.com/", deep=False)
    assert [r["id"] for r in res["checks"]] == IDS
