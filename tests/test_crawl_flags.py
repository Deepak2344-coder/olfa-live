"""The redirect flags must not punish the most common redirect on the web: bare domain -> www.domain."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from olfa_core.crawl import drop_same_site_flags  # noqa: E402


def _hops(*urls):
    return [{"url": u, "domain": u.split("//", 1)[-1].split("/", 1)[0], "status": 200,
             "kind": "http", "shortener": False, "error": None, "note": ""} for u in urls]


def test_bare_to_www_is_one_site():
    flags = ["domain_hopping", "final_domain_differs_from_origin"]
    out = drop_same_site_flags(flags, _hops("https://amazon.in", "https://www.amazon.in/"),
                               "https://amazon.in", "https://www.amazon.in/")
    assert out == [], out


def test_real_cross_domain_still_flagged():
    flags = ["domain_hopping", "final_domain_differs_from_origin"]
    hops = _hops("https://amazon.in", "https://amzn.to/x", "https://amazon.com/")
    out = drop_same_site_flags(flags, hops, "https://amazon.in", "https://amazon.com/")
    assert "domain_hopping" in out
    assert "final_domain_differs_from_origin" in out


def test_other_flags_survive():
    flags = ["domain_hopping", "https_downgrade", "final_domain_differs_from_origin"]
    out = drop_same_site_flags(flags, _hops("https://amazon.in", "https://www.amazon.in/"),
                               "https://amazon.in", "https://www.amazon.in/")
    assert out == ["https_downgrade"], out


def test_one_hop_chain_never_hops():
    out = drop_same_site_flags(["domain_hopping"], _hops("https://example.com/"),
                               "https://example.com/", "https://example.com/")
    assert out == []
