"""Hostname feature extractor. Shipped WITH the model so training and serving can never drift apart.

Deliberate choices (each fixes a shortcut the earlier models used):
  * scheme, 'www.', port, path and query are ignored: phishing and legitimate
    training URLs differed on those for dataset reasons, not real ones.
  * polarity: 1 = phishing, 0 = legitimate. Always.
"""
from __future__ import annotations
import math, re
from urllib.parse import urlsplit
import tldextract

_ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
VOWELS = set("aeiou")
KEYWORDS = ("login","signin","verify","secure","account","update","confirm","bank","wallet","support","service",
            "billing","password","unlock","suspend","kyc","free","bonus","invoice","alert","official","online","portal","pay")
BRANDS = ("paypal","google","microsoft","apple","amazon","netflix","facebook","instagram","whatsapp","linkedin","sbi","hdfc","icici","axis","paytm","phonepe","flipkart","irctc","dropbox","adobe","chase","wellsfargo","dhl","fedex","usps","outlook","office365")


def host_of(url: str) -> str:
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        h = (urlsplit(u).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


def registrable(host: str) -> str:
    e = _ext(host)
    return ".".join(p for p in (e.domain, e.suffix) if p) or host


def entropy(s: str) -> float:
    if not s: return 0.0
    n = len(s); c = {}
    for ch in s: c[ch] = c.get(ch, 0) + 1
    return -sum(v/n*math.log2(v/n) for v in c.values())


def numeric(host: str) -> dict:
    e = _ext(host)
    sub, dom, suf = e.subdomain, e.domain, e.suffix
    labels = host.split(".") if host else [""]
    letters = [c for c in dom if c.isalpha()]
    digits = sum(c.isdigit() for c in dom)
    vowel_ratio = sum(c in VOWELS for c in letters) / max(len(letters), 1)
    # longest run of consonants / digits inside the registrable label: random strings have long runs
    run = best = 0
    for c in dom:
        run = run + 1 if (c.isalpha() and c not in VOWELS) or c.isdigit() else 0
        best = max(best, run)
    flat = dom.replace("-", "")
    return {
        "host_len": len(host), "dom_len": len(dom), "sub_len": len(sub), "suffix_len": len(suf),
        "n_labels": len(labels), "sub_depth": len([p for p in sub.split(".") if p]),
        "n_hyphen_dom": dom.count("-"), "n_hyphen_host": host.count("-"), "n_digit_dom": digits,
        "digit_ratio_dom": digits / max(len(dom), 1), "digit_ratio_host": sum(c.isdigit() for c in host) / max(len(host), 1),
        "ent_dom": entropy(dom), "ent_host": entropy(host), "vowel_ratio": vowel_ratio, "max_cons_run": best,
        "longest_label": max(len(l) for l in labels), "is_ip": int(bool(re.fullmatch(r"[\d.]+", host)) or ":" in host),
        "punycode": int("xn--" in host), "kw_count": sum(k in host for k in KEYWORDS),
        "brand_in_sub": int(any(b in sub for b in BRANDS)), "brand_in_dom_not_exact": int(any(b in flat and flat != b for b in BRANDS)),
        "suffix_dots": suf.count("."), "sub_has_digits": int(any(c.isdigit() for c in sub)),
        "dom_is_hex_like": int(len(dom) >= 8 and all(c in "0123456789abcdef" for c in dom)),
    }
