from olfa_core import precautions
from olfa_core.schema import reason
from olfa_core.scanner import Scanner
from olfa_core.intel import Intel


def test_each_verdict_returns_tips():
    for level in ("safe", "suspicious", "dangerous"):
        assert precautions.build(level, [])


def test_safe_has_one_or_two_general_tips():
    assert 1 <= len(precautions.build("safe", [])) <= 2


def test_reason_specific_tips_appear():
    rs = [reason("credential_form_cross_origin", "x", "high"), reason("new_domain", "y", "low")]
    tips = precautions.build("dangerous", rs)
    assert any("login form" in t for t in tips)
    assert any("do not open" in t.lower() for t in tips)


def test_unknown_level_falls_back_to_safe_tips():
    assert precautions.build("weird", []) == precautions.SAFE_TIPS


def test_scan_result_has_precautions(tmp_path):
    sc = Scanner(intel=Intel(str(tmp_path / "i.db")))
    for url in ("https://example.com", "http://paypa1-secure-login.xyz/verify"):
        out = sc.scan(url, deep=False)
        assert isinstance(out["precautions"], list) and out["precautions"]
