import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from olfa_core import message
from olfa_core.intel import Intel
from olfa_core.scanner import Scanner


class FakeScanner:
    """Scanner stand-in: no network. Maps a substring of the URL to a (level, community) pair."""
    def __init__(self, table=None, intel_status=None):
        self.table, self.calls = table or {}, []
        outer = self

        class _I:
            def lookup(self, dom):
                return {"status": (intel_status or {}).get(dom, "unknown")}
        self.intel = _I()

    def scan(self, url, deep=True):
        self.calls.append(url)
        level, comm = "safe", "unknown"
        for k, v in self.table.items():
            if k in url:
                level, comm = v
        return {"level": level, "score": {"safe": .05, "suspicious": .5, "dangerous": .9}[level],
                "reasons": [{"message": f"{level} link"}] if level != "safe" else [],
                "intel": {"status": comm}, "final_url": url}


def test_extraction():
    out = message.extract("Call +91 98765 43210 or mail help@bank-help.com. Visit https://evil.example.com/a, www.foo.org and secure-pay.xyz/login")
    assert "https://evil.example.com/a" in out["urls"]
    assert any(u.startswith("www.foo.org") for u in out["urls"])
    assert "secure-pay.xyz/login" in out["urls"]
    assert out["emails"] == ["help@bank-help.com"]
    assert out["phones"] == ["+91 98765 43210"]
    assert not any("bank-help" in u for u in out["urls"])  # email domain is not a URL


def test_language_cues_categories():
    c = message.language_cues("URGENT: act now, buy a gift card and send your OTP. Dear customer")
    assert {"urgency", "payment_request", "credential_request", "impersonation"} <= set(c)


def test_urgency_only_is_not_fraudulent():
    r = message.analyze("URGENT!! Act now, your account will be suspended within 24 hours. Send your OTP and pay the fee.", FakeScanner())
    assert r["risk_class"] == "unverified"
    assert r["verified_evidence"] == []
    assert r["suspicious_language"]
    assert "fraudulent" not in r["label"].lower().replace("likely fraudulent:", "x") or r["risk_class"] != "fraudulent"
    assert r["precautions"]


def test_dangerous_link_is_fraudulent():
    sc = FakeScanner({"evil": ("dangerous", "unknown")})
    r = message.analyze("Please verify at https://evil.example.com/login", sc)
    assert r["risk_class"] == "fraudulent"
    assert r["verified_evidence"][0]["type"] == "flagged_link"


def test_community_confirmed_link_is_fraudulent():
    sc = FakeScanner({"shop": ("safe", "confirmed_malicious")})
    assert message.analyze("deal at https://shop.example.net", sc)["risk_class"] == "fraudulent"


def test_brand_mismatch_is_suspicious_evidence():
    r = message.analyze("Your PayPal account needs attention: https://account-check.qwzxv-demo.com/x", FakeScanner())
    assert r["risk_class"] == "suspicious"
    assert r["verified_evidence"][0]["type"] == "brand_mismatch"


def test_official_brand_link_is_clear():
    r = message.analyze("Your PayPal receipt: https://www.paypal.com/activity", FakeScanner())
    assert r["risk_class"] == "clear"


def test_clean_text_is_clear_with_tips():
    r = message.analyze("Lunch at 1pm tomorrow?", FakeScanner())
    assert r["risk_class"] == "clear" and r["precautions"]


def test_at_most_five_urls_scanned():
    sc = FakeScanner()
    text = " ".join(f"https://site{i}.example.com" for i in range(8))
    r = message.analyze(text, sc)
    assert len(sc.calls) == 5 and any("not checked" in n for n in r["notes"])


def test_gemini_failure_falls_back():
    def boom(_):
        raise RuntimeError("429")
    r = message.analyze("act now send gift card", FakeScanner(), explainer=boom)
    assert r["explanation_source"] == "built-in" and r["explanation"]


def test_gemini_text_used_but_class_unchanged():
    r = message.analyze("act now send gift card", FakeScanner(), explainer=lambda s: "Plain words. " + s["risk_class"])
    assert r["explanation_source"] == "gemini" and r["risk_class"] == "unverified"


def test_gemini_never_sees_raw_message():
    seen = {}
    message.analyze("secret@example.com act now https://x.example.com", FakeScanner(), explainer=lambda s: seen.update(s))
    assert "secret@example.com" not in str(seen) and "x.example.com" not in str(seen)


def test_gemini_explainer_uses_guarded_http_and_handles_block(monkeypatch):
    monkeypatch.setattr(message.guarded_http, "post_json", lambda *a, **k: {"status": None, "error": "blocked: x", "json": None})
    assert message.gemini_explainer("k")({"risk_class": "clear"}) is None
    monkeypatch.setattr(message.guarded_http, "post_json", lambda *a, **k: {"status": 200, "json": {"candidates": [{"content": {"parts": [{"text": " hi "}]}}]}})
    assert message.gemini_explainer("k")({}) == "hi"


def test_endpoint_limits_and_runs(monkeypatch):
    import app as appmod
    from fastapi import HTTPException
    from pydantic import ValidationError
    monkeypatch.setattr(appmod, "scanner", FakeScanner({"evil": ("dangerous", "unknown")}))
    monkeypatch.setattr(appmod, "DEFAULT_GEMINI_KEY", "")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    class Req:  # minimal stand-in for fastapi Request
        client = type("C", (), {"host": "1.2.3.4"})()
    r = appmod.analyze_message_endpoint(appmod.MessageRequest(text="go to https://evil.example.com now", deep=False), Req())
    assert r["risk_class"] == "fraudulent"
    with pytest.raises(ValidationError):
        appmod.MessageRequest(text="x" * 4001)
    with pytest.raises(ValidationError):
        appmod.MessageRequest(text="")
    appmod.message_limiter.limit_min = 1  # exhaust the limiter for this visitor
    appmod.message_limiter.minute_records.clear()
    appmod.message_limiter.check("9.9.9.9")
    class Req2:
        client = type("C", (), {"host": "9.9.9.9"})()
    with pytest.raises(HTTPException) as e:
        appmod.analyze_message_endpoint(appmod.MessageRequest(text="hi", deep=False), Req2())
    assert e.value.status_code == 429
