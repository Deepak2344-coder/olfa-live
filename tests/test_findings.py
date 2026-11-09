from test_core import PHISH_HTML, CLEAN_HTML, make_cert, serve  # helpers only
from olfa_core import cert as certmod, webcheck

FIELDS = ("issue", "evidence", "impact", "severity", "remediation", "limitations")


def _full(f):
    return all(f.get(k) for k in FIELDS) and f["severity"] in ("low", "medium", "high")


def test_every_page_finding_has_six_fields():
    srv, port = serve(PHISH_HTML)
    w = webcheck.check(f"http://localhost:{port}/", allow_private=True)
    assert w["reasons"]
    for r in w["reasons"]:
        assert _full(r), r["code"]
        assert "code" in r and "message" in r  # existing names kept
    failed = [c for c in w["web"]["checks"] if not c["ok"]]
    assert failed
    for c in failed:
        assert _full(c), c["name"]
    assert all("name" in c and "ok" in c for c in w["web"]["checks"])


def test_passing_checks_are_left_alone():
    srv, port = serve(CLEAN_HTML, headers={"strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'",
                                           "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY"})
    w = webcheck.check(f"http://localhost:{port}/", allow_private=True)
    assert all("issue" not in c for c in w["web"]["checks"] if c["ok"])


def test_every_cert_finding_has_six_fields(tmp_path):
    srv, port = serve(CLEAN_HTML, tls_cert=make_cert(), tmp_path=tmp_path)
    out = certmod.check("localhost", port, allow_private=True)
    assert out["reasons"]
    for r in out["reasons"]:
        assert _full(r), r["code"]
    assert "passive" in out["reasons"][0]["limitations"]
