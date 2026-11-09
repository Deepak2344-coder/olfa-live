"""Pillar 1b: lexical threat analysis (brand impersonation, typosquatting, URL tricks).

These rules are what the verdict leans on for URL-only evidence, because the
bundled ML model is biased (see README: it keys on a `www.` prefix and a bare
path). Every function is pure and offline.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlsplit

from .schema import reason
from .urlparts import host_of, is_ip, split_domain
from .popular import is_popular

# brand -> official registrable domains
BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com", "githubusercontent.com"],
    "dropbox": ["dropbox.com"],
    "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
}
_OFFICIAL = {d for ds in BRANDS.values() for d in ds}

# Domains never treated as impersonators by lexical rules.
TRUSTED_SUFFIXES = ("gov.in", "nic.in", "ac.in", "edu.in", "edu", "gov")

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "kim", "work", "zip", "mov", "rest", "cfd", "sbs", "icu"}
SENSITIVE_WORDS = ("login", "signin", "verify", "secure", "account", "update", "confirm", "kyc", "wallet", "password", "suspend", "unlock", "billing")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})

# Look-alike characters (Cyrillic/Greek/fullwidth) folded to Latin, so
# 'xn--pypal-4ve' (paypal with a Cyrillic а) is compared as 'paypal'.
# Keys are code points: str.translate() ignores anything else.
_CONFOUSABLES = {
    ord("а"): ord("a"), ord("в"): ord("b"), ord("с"): ord("c"), ord("е"): ord("e"),
    ord("і"): ord("i"), ord("ј"): ord("j"), ord("к"): ord("k"), ord("м"): ord("m"),
    ord("н"): ord("h"), ord("о"): ord("o"), ord("р"): ord("p"), ord("ѕ"): ord("s"),
    ord("т"): ord("t"), ord("х"): ord("x"), ord("у"): ord("y"), ord("ԁ"): ord("d"),
    ord("һ"): ord("h"), ord("ӏ"): ord("l"), ord("ϳ"): ord("j"), ord("ɡ"): ord("g"),
    ord("ι"): ord("i"), ord("ο"): ord("o"), ord("ρ"): ord("p"), ord("τ"): ord("t"),
    ord("ε"): ord("e"), ord("α"): ord("a"), ord("ν"): ord("v"), ord("κ"): ord("k"),
    ord("γ"): ord("y"), ord("ϲ"): ord("c"),
    **{0xFF41 + i: 0x61 + i for i in range(26)},  # fullwidth a-z
    **{0xFF21 + i: 0x41 + i for i in range(26)},  # fullwidth A-Z
}
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)


def fold_homoglyphs(s: str) -> str:
    """Fold punycode/look-alike/zero-width tricks into plain Latin text."""
    if "xn--" in s:
        s = ".".join(_decode_label(p) for p in s.split("."))
    return s.translate(_ZERO_WIDTH).translate(_CONFOUSABLES).lower()


def _decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except Exception:  # noqa: BLE001 - malformed punycode: keep the raw label
            return label
    return label


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(host: str) -> bool:
    _, reg, _ = split_domain(host)
    return reg in _OFFICIAL or reg.endswith(TRUSTED_SUFFIXES)


def brand_findings(url: str) -> List[dict]:
    parts = urlsplit(url)
    host = host_of(url)
    sub, reg, suffix = split_domain(host)
    out: List[dict] = []
    if not host or is_ip(host) or is_official(host):
        return out
    if is_popular(reg):  # established top-100k site: name-based look-alike guesses don't apply
        return out
    label = reg.split(".")[0] if reg else ""
    folded = fold_homoglyphs(label)  # xn--pypal-4ve -> 'paypal', fullwidth/zero-width folded
    homoglyph = folded != label
    flat_label = folded.translate(_LEET)  # digit swaps: paypa1 -> paypal
    haystack_sub = fold_homoglyphs(sub).translate(_LEET)
    path = (parts.path or "").lower()
    for brand, domains in BRANDS.items():
        official_labels = {d.split(".")[0] for d in domains}
        # 1. close misspelling of the brand's own label (paypa1, g00gle, arnazon…)
        for off in official_labels:
            if len(off) >= 4 and label not in official_labels:
                dist = levenshtein(flat_label, off)
                if dist <= 1 or (len(off) >= 7 and levenshtein(folded, off) <= 2):
                    details = {"brand": brand, "distance": dist, "domain": reg}
                    if homoglyph:
                        details["homoglyph"] = folded
                    out.append(reason("typosquat", f"The domain '{reg}' imitates {off}.com but is not the real site.",
                                      "high", details, "threat"))
                    break
        else:
            # 2. brand name embedded in the registrable label (paypal-login-secure.com)
            if len(brand) >= 4 and brand in flat_label.replace("-", ""):
                out.append(reason("brand_impersonation", f"'{reg}' uses the name {brand} but is not run by {brand}.",
                                  "high", {"brand": brand, "domain": reg, **({"homoglyph": folded} if homoglyph else {})}, "threat"))
            # 3. brand as a subdomain or in the path of a foreign domain (paypal.com.evil.tk, /paypal/login)
            elif len(brand) >= 4 and (brand in haystack_sub.replace("-", "") or f"/{brand}" in path):
                out.append(reason("brand_impersonation", f"The address mentions {brand} but is hosted on '{reg}'.",
                                  "high", {"brand": brand, "domain": reg}, "threat"))
    seen, deduped = set(), []
    for r in out:  # one finding per brand
        b = r["details"]["brand"]
        if b not in seen:
            seen.add(b)
            deduped.append(r)
    return deduped[:2]


def url_findings(url: str) -> List[dict]:
    """Structural tricks that are rare on legitimate sites."""
    parts = urlsplit(url)
    host = host_of(url)
    sub, reg, suffix = split_domain(host)
    out: List[dict] = []
    if is_ip(host):
        out.append(reason("ip_address_host", "The link uses a raw IP address instead of a domain name.", "high", {"host": host}, "threat"))
    if "@" in (parts.netloc or ""):
        out.append(reason("suspicious_url_pattern", "The address contains '@', which can hide the real destination.", "high", {"pattern": "userinfo"}, "threat"))
    if "xn--" in host:
        out.append(reason("punycode_domain", "The domain uses punycode (xn--), often used for look-alike characters.", "medium", {"host": host}, "threat"))
    if suffix.split(".")[-1] in RISKY_TLDS:
        out.append(reason("suspicious_url_pattern", f"The '.{suffix.split('.')[-1]}' ending is heavily abused by phishing sites.", "low", {"pattern": "risky_tld"}, "threat"))
    if sub.count(".") >= 3:
        out.append(reason("suspicious_url_pattern", "The address stacks many subdomains, a common way to bury the real domain.", "medium", {"pattern": "many_subdomains"}, "threat"))
    words = [w for w in SENSITIVE_WORDS if w in host.replace("-", "")]
    if len(words) >= 2 or (words and host.count("-") >= 2):
        out.append(reason("suspicious_url_pattern", "The domain name packs in credential words like " + ", ".join(words[:3]) + ".", "medium", {"pattern": "credential_words", "words": words}, "threat"))
    if parts.port not in (None, 80, 443):
        out.append(reason("suspicious_url_pattern", f"The link uses an unusual port ({parts.port}).", "low", {"pattern": "odd_port"}, "threat"))
    if parts.scheme == "http" and (words or re.search(r"(login|signin|verify|password)", parts.path.lower())):
        out.append(reason("no_https", "A page that looks like a login is served over plain http.", "medium", {}, "threat"))
    if len(url) >= 400:
        out.append(reason("long_url", f"The link is extremely long ({len(url)} characters); long links are often used to hide the real destination.",
                          "medium", {"length": len(url)}, "threat"))
    elif len(url) >= 160:
        out.append(reason("long_url", f"The link is unusually long ({len(url)} characters).", "low", {"length": len(url)}, "threat"))
    return out


def analyze(url: str) -> List[dict]:
    return brand_findings(url) + url_findings(url)
