"""DNS and hosting facts: A/AAAA, NS, MX and the hosting ASN, with a few evidence-based flags.

Everything goes through the SSRF guard (guarded_http) to public DNS-over-HTTPS resolvers; the ASN comes
from Team Cymru's DNS service over the same channel (no key needed). If a lookup cannot run, the field
is reported as not checked and no reason is raised: a flag is only produced from data we really got.
Not implemented (no free source): "many unrelated domains on one IP" (needs reverse-IP data).
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from . import domainage, guarded_http
from .schema import reason
from .urlparts import is_ip, registrable

ENDPOINTS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
TYPES = {"A": 1, "NS": 2, "MX": 15, "TXT": 16, "AAAA": 28}
TTL = 600
NEW_NS_DAYS = 30
_cache: Dict[tuple, tuple] = {}


def _query(name: str, rtype: str) -> Dict[str, Any]:
    """{"ok": bool, "answers": [str]}; ok=False means no resolver answered (unknown, not 'empty')."""
    key = (name, rtype)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < TTL:
        return hit[1]
    out: Dict[str, Any] = {"ok": False, "answers": []}
    for ep in ENDPOINTS:
        r = guarded_http.request("GET", f"{ep}?{urlencode({'name': name, 'type': rtype})}",
                                 headers={"accept": "application/dns-json"}, timeout=4)
        if r.get("status") != 200:
            continue
        try:
            j = json.loads(r["body"])
        except (ValueError, TypeError):
            continue
        if j.get("Status") not in (0, 3):  # NOERROR / NXDOMAIN are real answers
            continue
        out = {"ok": True, "answers": [a["data"].strip().rstrip(".") for a in j.get("Answer", []) if a.get("type") == TYPES[rtype]]}
        break
    if out["ok"]:
        _cache[key] = (time.time(), out)
    return out


def _asn(ip: str) -> Optional[Dict[str, str]]:
    if ":" in ip:
        return None  # IPv6 ASN lookup not implemented
    rev = ".".join(reversed(ip.split(".")))
    o = _query(f"{rev}.origin.asn.cymru.com", "TXT")
    if not o["ok"] or not o["answers"]:
        return None
    parts = [p.strip() for p in o["answers"][0].strip('"').split("|")]
    if len(parts) < 3:
        return None
    asn = parts[0].split()[0]
    info = {"asn": "AS" + asn, "prefix": parts[1], "country": parts[2], "org": None}
    n = _query(f"AS{asn}.asn.cymru.com", "TXT")
    if n["ok"] and n["answers"]:
        bits = [p.strip() for p in n["answers"][0].strip('"').split("|")]
        info["org"] = bits[-1] if bits else None
    return info


def lookup(host: str) -> Dict[str, Any]:
    """Never raises. status: ok | partial | not_run | n/a."""
    info: Dict[str, Any] = {"host": host, "status": "not_run", "a": [], "aaaa": [], "ns": [], "mx": [], "mx_checked": False,
                            "ns_checked": False, "asn": None, "ns_age": {}, "notes": []}
    if not host or is_ip(host):
        info["status"] = "n/a"
        return info
    reg = registrable(host) or host
    try:
        a, aaaa, ns, mx = (_query(host, "A"), _query(host, "AAAA"), _query(reg, "NS"), _query(reg, "MX"))
        info.update(a=a["answers"], aaaa=aaaa["answers"], ns=ns["answers"], mx=[m.split()[-1].rstrip(".") for m in mx["answers"]],
                    mx_checked=mx["ok"], ns_checked=ns["ok"])
        oks = [a["ok"], aaaa["ok"], ns["ok"], mx["ok"]]
        info["status"] = "ok" if all(oks) else "partial" if any(oks) else "not_run"
        if a["answers"]:
            info["asn"] = _asn(a["answers"][0])
        ns_regs = []
        for n in ns["answers"]:
            r = registrable(n)
            if r and r != reg and r not in ns_regs:
                ns_regs.append(r)
        if ns_regs:
            with ThreadPoolExecutor(max_workers=3) as pool:
                for r, age in zip(ns_regs[:3], pool.map(lambda x: domainage.lookup(x), ns_regs[:3])):
                    info["ns_age"][r] = age.get("age_days")
    except Exception as exc:  # noqa: BLE001 - DNS facts are optional
        info["status"] = "not_run"
        info["notes"].append(type(exc).__name__)
    if info["status"] == "not_run":
        info["notes"].append("DNS lookups were not available, so this check was not run.")
    return info


def reasons(info: Optional[Dict[str, Any]], existing_codes: set) -> List[dict]:
    out: List[dict] = []
    if not info or info.get("status") in (None, "not_run", "n/a"):
        return out
    for ns_reg, age in (info.get("ns_age") or {}).items():
        if age is not None and age < NEW_NS_DAYS:
            out.append(reason("new_nameserver", f"The domain's name servers belong to {ns_reg}, which was registered only {age} days ago.",
                              "medium", {"nameserver_domain": ns_reg, "age_days": age}, "dns"))
    lookalike = bool({"brand_impersonation", "typosquat"} & existing_codes)
    if lookalike and info.get("mx_checked") and not info.get("mx") and (info.get("a") or info.get("aaaa")):
        out.append(reason("no_mail_records", "This brand look-alike domain has no mail (MX) records, so it is not set up for real email.",
                          "low", {"mx": []}, "dns"))
    return out
