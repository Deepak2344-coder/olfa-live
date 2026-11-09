"""Step 5: threat correlation.

Links are decided ONLY by deterministic rules over recorded facts (shared IP, ASN, nameserver,
certificate fingerprint, impersonated brand, same registrable domain). Each link carries the exact
evidence that produced it. Nothing here calls an AI; any wording is built from the evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .urlparts import host_of, registrable

BRAND_CODES = ("brand_impersonation", "typosquat")
# Providers shared by millions of sites: a shared nameserver or network says little by itself.
COMMON_NS = ("cloudflare.com", "awsdns", "googledomains.com", "domaincontrol.com", "registrar-servers.com",
             "azure-dns", "google.com", "nsone.net", "wixdns.net", "squarespacedns.com")
STRENGTH_ORDER = {"strong": 0, "medium": 1, "weak": 2}
MAX_LINKS = 20
INFRA_RULES = ("shared_ip", "shared_nameserver", "shared_network")


def normalize_brand(brand: Optional[str]) -> str:
    return "".join(ch for ch in (brand or "").lower() if ch.isalnum())


def brand_of_host(host_or_domain: str) -> str:
    """Impersonated brand for a hostname by the lexical rules, or '' (also used to backfill old reports)."""
    from . import heuristics  # lazy: keeps imports light for intel.py
    host = host_or_domain if "://" not in host_or_domain else (host_of(host_or_domain) or host_or_domain)
    for r in heuristics.brand_findings("http://" + host + "/"):
        if r.get("code") in BRAND_CODES:
            b = normalize_brand((r.get("details") or {}).get("brand"))
            if b:
                return b
    return ""


def facts_from_scan(result: Dict[str, Any]) -> Dict[str, List[str]]:
    """Pull correlatable facts from a finished scan result. Only real, observed values are returned."""
    facts: Dict[str, List[str]] = {}
    dns = result.get("dns") or {}
    ips = [*(dns.get("a") or []), *(dns.get("aaaa") or [])]
    if ips:
        facts["ip"] = ips[:6]
    asn = dns.get("asn") or {}
    if asn.get("asn"):
        facts["asn"] = [asn["asn"]]
    if dns.get("ns"):
        facts["ns"] = [n.rstrip(".") for n in dns["ns"][:6]]
    chain = (result.get("certificate") or {}).get("chain") or []
    if chain and chain[0].get("sha256"):
        facts["cert"] = [chain[0]["sha256"]]
    brands = [normalize_brand((r.get("details") or {}).get("brand")) for r in result.get("reasons", [])
              if r.get("code") in BRAND_CODES]
    brands = [b for b in brands if b]
    if brands:
        facts["brand"] = brands[:1]
    return facts


def _is_common_ns(ns: str) -> bool:
    return any(p in ns for p in COMMON_NS)


def related(intel, url_or_host: str) -> Dict[str, Any]:
    """Related domains and reports for a URL, with the matching evidence for every link."""
    host = host_of(url_or_host if "://" in url_or_host else "http://" + url_or_host) or url_or_host.lower()
    domain = registrable(host) or host
    mine = intel.observations(domain)
    brand = brand_of_host(host) or (mine.get("brand") or [""])[0]
    if brand and brand not in mine.get("brand", []):
        mine.setdefault("brand", []).append(brand)

    links: Dict[str, Dict[str, Any]] = {}

    def add(other: str, rule: str, strength: str, evidence: Dict[str, Any]) -> None:
        entry = links.setdefault(other, {"domain": other, "matches": []})
        if not any(m["rule"] == rule and m["evidence"] == evidence for m in entry["matches"]):
            entry["matches"].append({"rule": rule, "strength": strength, "evidence": evidence})

    for ip in mine.get("ip", []):
        for other in intel.domains_with("ip", ip, domain):
            add(other, "shared_ip", "medium", {"ip": ip})
    for fp in mine.get("cert", []):
        for other in intel.domains_with("cert", fp, domain):
            add(other, "shared_certificate", "strong", {"sha256": fp})
    for ns in mine.get("ns", []):
        for other in intel.domains_with("ns", ns, domain):
            add(other, "shared_nameserver", "weak" if _is_common_ns(ns) else "medium", {"nameserver": ns})
    for asn in mine.get("asn", []):
        for other in intel.domains_with("asn", asn, domain):
            add(other, "shared_network", "weak", {"asn": asn})
    if brand:
        for other in intel.domains_with("brand", brand, domain):
            add(other, "same_impersonated_brand", "medium", {"brand": brand})

    own = intel.lookup(domain)
    own_flagged = own["status"] in ("confirmed_malicious", "reported")
    out: List[Dict[str, Any]] = []
    for other, entry in links.items():
        status = intel.lookup(other)
        matches = sorted(entry["matches"], key=lambda m: STRENGTH_ORDER[m["strength"]])
        flagged = status["status"] in ("confirmed_malicious", "reported")
        best = matches[0]["strength"]
        # Shared hosting is common: infrastructure-only links need a community threat report on either side,
        # and weak ones (big shared providers) on the other domain itself.
        infra_only = all(m["rule"] in INFRA_RULES for m in matches)
        if infra_only and not (flagged or own_flagged):
            continue
        if best == "weak" and not flagged:
            continue
        out.append({"domain": other, "strength": best, "matches": matches, "community_status": status["status"],
                    "threat_reports": status["threat_reports"]})
    out.sort(key=lambda l: (STRENGTH_ORDER[l["strength"]], -l["threat_reports"], l["domain"]))
    out = out[:MAX_LINKS]

    reports = [{"url": u} for u in intel.report_domains(domain)[:10]] if own["threat_reports"] + own["safe_reports"] else []
    return {"domain": domain, "impersonated_brand": brand or None, "observed": {k: v[:4] for k, v in mine.items() if k != "brand"},
            "community_status": own["status"], "reports": reports, "related": out,
            "summary": summarize(domain, brand, out, own),
            "method": "Links come from deterministic matching of recorded facts, not from AI. Shared hosting is weak evidence by itself."}


def summarize(domain: str, brand: str, links: List[Dict[str, Any]], own: Dict[str, Any]) -> str:
    if not links:
        return f"No related incidents are recorded for {domain} yet."
    strong = [l for l in links if l["strength"] == "strong"]  # same certificate fingerprint
    flagged = [l for l in links if l["community_status"] in ("confirmed_malicious", "reported")]
    parts = [f"{len(links)} related domain(s) found for {domain}"]
    if strong:
        parts.append(f"{len(strong)} share infrastructure directly (same certificate)")
    if flagged:
        parts.append(f"{len(flagged)} already carry community threat reports")
    if brand:
        parts.append(f"the impersonated brand is {brand}")
    return "; ".join(parts) + "."
