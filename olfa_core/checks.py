"""Builds the per-scan "what was checked on this link" panel.

One row per signal group, in the order the UI shows them. Every reason of a
scan is claimed by exactly one row (unclaimed ones get an "other" row, which a
test asserts never appears for the codes we know). A row's state is one of:

    fired          the check ran and found something (severity attached)
    clean          the check ran and found nothing
    not_run        the check did not run (quick scan / fetch failed) -> shown as "not checked"
    not_applicable there is nothing to check (certificate on a plain http link)
    unknown        the check ran but the data source had no answer (domain age)
"""
from __future__ import annotations

from typing import Dict, List, Optional

# id, label shown in the UI, reason codes this row claims
ROWS = [
    ("ip_host", "IP address in URL", {"ip_address_host"}),
    ("url_patterns", "@ symbol, many subdomains, hyphens", {"suspicious_url_pattern"}),
    ("url_length", "URL length", {"long_url"}),
    ("homoglyph", "Typosquatting and homoglyphs", {"typosquat", "brand_impersonation", "punycode_domain"}),
    ("certificate", "HTTPS and certificate",
     {"no_https", "self_signed_certificate", "bad_certificate", "cert_expired", "expiring_certificate",
      "cert_hostname_mismatch", "weak_tls", "new_certificate"}),
    ("redirects", "Redirect chain",
     {"too_many_hops", "shortener_used", "domain_hopping", "final_domain_differs_from_origin",
      "https_downgrade", "redirect_loop", "blocked_private_address", "fetch_failed"}),
    ("form_actions", "External form actions", {"credential_form_cross_origin", "credentials_over_http"}),
    ("hidden_iframes", "Hidden iframes", {"hidden_iframe"}),
    ("obfuscated_script", "Obfuscated script", {"obfuscated_script"}),
    ("link_targets", "# and javascript: links", {"javascript_link_payload", "hidden_link_targets"}),
    ("page_basics", "Headers, cookies and pressure wording", {"cookies_missing_secure", "urgency_language"}),
    ("domain_age", "Domain age", {"new_domain"}),
    ("link_model", "Link-pattern model (ML)", {"ml_phishing_url"}),
    ("community", "Community reports", {"community_confirmed", "community_reported"}),
]

URL_ROWS = {"ip_host", "url_patterns", "url_length", "homoglyph"}   # run on every scan, online or not
ALWAYS_ROWS = {"community"}                                          # local database, always runs
DEEP_ROWS = {"redirects", "domain_age"}                              # only in a full scan
PAGE_ROWS = {"form_actions", "hidden_iframes", "obfuscated_script", "link_targets", "page_basics"}
_SEV_ORDER = {"high": 3, "medium": 2, "low": 1}


def _claim(r: dict) -> str:
    code = r.get("code")
    for rid, _label, codes in ROWS:
        if code in codes:
            return rid
    if r.get("source") == "certificate":
        return "certificate"
    if r.get("source") == "intel":
        return "community"
    return "other"


def _entry(rid: str, label: str, state: str, reasons: Optional[List[dict]] = None, note: str = "",
           severity: Optional[str] = None) -> dict:
    return {"id": rid, "label": label, "state": state, "severity": severity, "note": note,
            "reasons": [{"code": r["code"], "message": r["message"], "severity": r.get("severity", "medium")}
                        for r in (reasons or [])]}


def build(*, reasons: List[dict], status: Dict[str, str], deep: bool,
          domain_age: Optional[Dict[str, object]] = None) -> List[dict]:
    """Assemble the panel rows for one scan result."""
    labels = {rid: label for rid, label, _ in ROWS}
    claimed: Dict[str, List[dict]] = {}
    for r in reasons:
        claimed.setdefault(_claim(r), []).append(r)

    web_status = status.get("web", "ok")
    cert_status = status.get("certificate", "ok")
    out: List[dict] = []

    for rid, label, _codes in ROWS:
        fired = claimed.get(rid, [])
        severity = max((r.get("severity", "medium") for r in fired),
                       key=lambda s: _SEV_ORDER.get(s, 0), default=None) if fired else None

        state, note = "clean", ""
        if rid in URL_ROWS or rid in ALWAYS_ROWS:
            pass  # ran on every scan
        elif rid == "certificate":
            if cert_status.startswith("n/a"):
                state, note = "not_applicable", "the link is plain http, so there is no certificate"
            elif cert_status != "ok":
                state, note = "not_run", cert_status
        elif rid in DEEP_ROWS:
            if not deep:
                state, note = "not_run", "full scan only (uncheck 'Quick check only')"
            elif rid == "domain_age":
                info = domain_age or {}
                if info.get("age_days") is None:
                    if info.get("error") == "not_a_domain":
                        state, note = "not_applicable", "the link is a raw IP address"
                    else:
                        state, note = "unknown", f"no registration data ({info.get('error') or 'no answer'})"
                else:
                    note = f"registered {info.get('registered')} ({info.get('age_days')} days ago)"
        elif rid in PAGE_ROWS:
            if web_status != "ok":
                state, note = "not_run", web_status

        if fired:
            state = "fired"
        out.append(_entry(rid, label, state, fired, note, severity))

    if claimed.get("other"):
        out.append(_entry("other", "Other signals", "fired", claimed["other"], "",
                          max((r.get("severity", "medium") for r in claimed["other"]),
                              key=lambda s: _SEV_ORDER.get(s, 0))))
    return out
