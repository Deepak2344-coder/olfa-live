"""Orchestrates the four pillars for one URL."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from . import cert as certmod
from . import domainage, heuristics, webcheck
from .checks import build as build_checks
from .crawl import crawl
from .fusion import fuse
from .intel import Intel
from .schema import reason
from .url_model import UrlModel
from .urlparts import host_of, normalize_url, port_of, registrable

ROOT = Path(__file__).resolve().parent.parent


def _network_note(host: str, detail: str) -> str:
    import re as _re
    m = _re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,})\)?\s*$", detail or "")
    ip = m.group(1) if m else "a local address"
    return (f"Your network or DNS says {host} is at {ip}, which is private, so Olfa did not connect to it. "
            "This usually means a VPN, proxy or filtering DNS is in the way. Turn it off, or set OLFA_ALLOW_CIDRS "
            f"(for example 198.18.0.0/15) if you know that range is safe. This is not counted against the site.")

FLAG_REASONS = {
    "too_many_hops": ("The link bounces through more than 10 redirects.", "medium"),
    "shortener_used": ("A link shortener hides the real destination.", "low"),
    "domain_hopping": ("The redirect chain crosses several different domains.", "medium"),
    "final_domain_differs_from_origin": ("The link lands on a different domain than it started on.", "medium"),
    "https_downgrade": ("The chain drops from https to plain http.", "high"),
    "redirect_loop": ("The redirect chain loops back on itself.", "high"),
    "blocked_private_address": ("A redirect pointed at a private network address.", "high"),
}


class Scanner:
    def __init__(self, model_dir: Optional[Path] = None, intel: Optional[Intel] = None, *, allow_private: bool = False):
        self.model = UrlModel(model_dir or ROOT / "models")
        self.intel = intel or Intel(str(ROOT / "olfa_intel.db"))
        self.allow_private = allow_private  # tests only; the API never sets this
        self._cache: Dict[tuple, tuple] = {}

    def scan(self, raw_url: str, *, deep: bool = True) -> Dict[str, Any]:
        url = normalize_url(raw_url)
        key = (url, deep)
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < 300:
            return hit[1]
        started = time.time()
        status = {p: "ok" for p in ("threat", "web", "certificate", "intel")}

        # --- pillar 1: threat analysis (ML + lexical), on the link as given
        threat = heuristics.analyze(url)
        ml = None
        if self.model.available:
            try:
                ml = self.model.predict(url)
            except Exception:  # noqa: BLE001 - a broken model must never break a scan
                status["threat"] = "partial"
        else:
            status["threat"] = "partial"

        notes: List[str] = []
        final_url, hops, trace_info = url, [], None
        web_reasons: List[dict] = []
        cert_reasons: List[dict] = []
        cert_info = web_info = None
        age_info: Optional[Dict[str, object]] = None
        redirect_reasons: List[dict] = []

        if deep:
            trace_info = crawl(url, allow_private=self.allow_private)
            final_url, hops, final_page = trace_info["final_url"], trace_info["hops"], trace_info["final_page"]
            first = hops[0] if hops else {}
            origin_blocked = first.get("kind") == "blocked"
            if origin_blocked:  # the link itself resolves privately: a local-network fact, not evidence about the site
                notes.append(_network_note(host_of(url), str(first.get("error"))))
                trace_info["flags"] = [f for f in trace_info["flags"] if f != "blocked_private_address"]
            elif trace_info.get("resolved_via") == "doh":
                notes.append(f"Your system DNS gave a private address for {host_of(url)}, so Olfa looked the real address up "
                             "through a public DNS-over-HTTPS resolver (Cloudflare/Google) and checked that instead.")
            for flag in trace_info["flags"]:
                if flag in FLAG_REASONS:
                    msg, sev = FLAG_REASONS[flag]
                    redirect_reasons.append(reason(flag, msg, sev, {"hops": len(hops)}, "threat"))
            # If we landed elsewhere, lexical analysis of the destination matters most.
            if registrable(host_of(final_url)) != registrable(host_of(url)):
                threat += [r for r in heuristics.analyze(final_url) if r["code"] not in {x["code"] for x in threat}]
            threat += redirect_reasons

            # page security: reuse the page the crawler already fetched
            if final_page is not None:
                w = webcheck.assess(final_page, final_url)
                web_info, web_reasons = w["web"], w["reasons"]
            else:
                status["web"] = "unavailable"
                web_info = {"fetched": False, "error": trace_info.get("error"), "checks": [], "grade": None, "score": None}

            # certificate: only meaningful for https destinations we could reach
            # domain age: RDAP lookup runs in parallel with the certificate check
            fhost = host_of(final_url)
            with ThreadPoolExecutor(max_workers=2) as pool:
                age_future = pool.submit(domainage.lookup, fhost)
                if urlsplit(final_url).scheme == "https":
                    c = pool.submit(certmod.check, fhost, port_of(final_url) or 443,
                                    allow_private=self.allow_private).result()
                    cert_info, cert_reasons = c["cert"], c["reasons"]
                    if cert_info.get("level") == "gray":
                        status["certificate"] = "unavailable"
                else:
                    status["certificate"] = "n/a (http)"
                    cert_reasons = [reason("no_https", "The destination is served over plain http, so there is no certificate to protect it.", "medium", {}, "certificate")]
                age_info = age_future.result()
            threat += domainage.reasons(age_info)
        else:
            status["web"] = status["certificate"] = "skipped (quick scan)"

        # --- pillar 4: community intel for the link and where it lands
        lookups = [self.intel.lookup(url)]
        if registrable(host_of(final_url)) != registrable(host_of(url)):
            lookups.append(self.intel.lookup(final_url))
        rank = {"confirmed_malicious": 5, "reported": 4, "disputed": 3, "confirmed_safe": 2, "reported_safe": 1, "unknown": 0}
        best = max(lookups, key=lambda l: rank[l["status"]])
        intel_reasons = [r for l in lookups for r in self.intel.reasons_for(l)]

        # webcheck's brand finding duplicates lexical ones: keep the stronger copy only
        seen_codes = {(r["code"], (r.get("details") or {}).get("brand")) for r in threat}
        web_reasons = [r for r in web_reasons if (r["code"], (r.get("details") or {}).get("brand")) not in seen_codes or r["code"] not in ("brand_impersonation", "typosquat")]

        result = fuse(url, threat=threat, web=web_reasons, cert=cert_reasons, intel=intel_reasons, ml=ml,
                      intel_status=best["status"], status=status,
                      extra={"final_url": final_url, "redirects": hops, "certificate": cert_info,
                             "web_assessment": web_info, "intel": best, "deep": deep, "notes": notes,
                             "elapsed_ms": int((time.time() - started) * 1000)})
        result["components"] = self._components(result, ml, web_info, cert_info, best, status, web_reasons, cert_reasons)
        result["checks"] = build_checks(reasons=result["reasons"], status=status, deep=deep, domain_age=age_info)
        self._cache[key] = (time.time(), result)
        if len(self._cache) > 500:
            self._cache.pop(next(iter(self._cache)))
        return result

    @staticmethod
    def _components(result, ml, web_info, cert_info, intel, status, web_reasons, cert_reasons) -> Dict[str, Any]:
        """The four things the overall verdict is built from, each in one place for the UI."""
        codes = {r["code"] for r in result["reasons"]}
        web_info = web_info or {}
        cert_info = cert_info or {}
        return {
            "ml": {"risk_pct": round(ml["risk"] * 100) if ml else None, "counted": "ml_phishing_url" in codes,
                   "popular_domain": bool(ml and ml.get("popular_domain"))},
            "page_security": {"status": status["web"], "grade": web_info.get("grade"), "score": web_info.get("score"),
                              "findings": [r["code"] for r in web_reasons]},
            "certificate": {"status": status["certificate"], "level": cert_info.get("level"),
                            "trusted": cert_info.get("verified"), "days_left": cert_info.get("days_left"),
                            "findings": [r["code"] for r in cert_reasons]},
            "community": {"status": intel["status"], "unsafe_reports": intel["threat_reports"], "safe_reports": intel["safe_reports"]},
            "overall": {"score": result["score"], "level": result["level"], "rules": [
                "Each check turns its findings into a 0-1 score (high 0.55, medium 0.25, low 0.08 each); several weak findings add up, one weak finding never makes a site dangerous.",
                "The ML score counts only at 0.95+ AND when another check also found something; it is ignored for the 100,000 most popular domains.",
                "Community: confirmed-malicious forces at least 0.90; confirmed-safe lowers the score unless a high-severity finding exists.",
                "A check that could not run is shown as not checked. It is never counted as safe."]},
        }
