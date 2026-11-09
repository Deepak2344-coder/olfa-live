"""Adds the six report fields (issue, evidence, impact, severity, remediation, limitations) to
page and certificate findings. Text is deterministic; checks stay passive (one page, no probing)."""

from __future__ import annotations

from typing import Any, Dict, List

PAGE_LIMIT = "Checked one page only, passively. The page script was never run and no forms were submitted."
CERT_LIMIT = "Checked one passive TLS handshake from this server. Results can differ by network location and over time."

# code -> (issue, impact, remediation)
CATALOG = {
    "cookies_missing_secure": ("Cookies set without the Secure flag",
        "Cookies could be sent over an unencrypted connection and read by someone on the same network.",
        "Add the Secure attribute (and HttpOnly and SameSite where suitable) to every cookie."),
    "credential_form_cross_origin": ("Login form submits to a different site",
        "Entered passwords are delivered to another party, the classic phishing pattern.",
        "Post credentials only to the site's own origin. Visitors should not sign in on this page."),
    "credentials_over_http": ("Login form submits without encryption",
        "Passwords can be read in transit by anyone on the network path.",
        "Serve the page and the form target over HTTPS and redirect all http traffic."),
    "hidden_iframe": ("Hidden frame from another site",
        "A concealed third-party frame can load tracking, malware or clickjacking content without the visitor noticing.",
        "Remove the frame or make it visible, and restrict embeds with a Content-Security-Policy."),
    "obfuscated_script": ("Obfuscated script on the page",
        "Disguised code is often used to hide redirects, skimmers or malware.",
        "Replace it with readable, reviewed code. Visitors should treat the page as untrustworthy."),
    "javascript_link_payload": ("Links that run script instead of opening a page",
        "Script links can trigger hidden actions when clicked.",
        "Use normal links and move behaviour into reviewed event handlers."),
    "hidden_link_targets": ("Link text that hides a different destination",
        "Visitors can be sent somewhere other than what the link appears to say.",
        "Make the visible text match the real destination."),
    "urgency_language": ("Pressure wording on the page",
        "Urgent wording is used to rush people into handing over details.",
        "Remove pressure language from official pages. Visitors should slow down and verify independently."),
    "brand_impersonation": ("Page presents a well-known brand on another domain",
        "Visitors may trust the page and hand over credentials meant for the real brand.",
        "If this is your brand, take the page down. Otherwise visitors should use the brand's real address."),
    "self_signed_certificate": ("Self-signed certificate",
        "Nothing independent vouches for the site, so a man-in-the-middle cannot be told apart from the real server.",
        "Install a certificate from a trusted authority (free ones exist)."),
    "bad_certificate": ("Certificate not trusted",
        "Browsers will warn visitors, and the connection cannot be verified as private or genuine.",
        "Install a valid certificate with the full chain from a trusted authority."),
    "cert_expired": ("Expired certificate",
        "Browsers show a full-page warning and the connection cannot be verified.",
        "Renew the certificate now and automate renewal."),
    "expiring_certificate": ("Certificate expires soon",
        "The site will show security errors once the certificate expires.",
        "Renew before the expiry date and automate renewal."),
    "cert_hostname_mismatch": ("Certificate issued for a different name",
        "The certificate does not prove this address is the site it claims to be.",
        "Issue a certificate that lists this exact hostname."),
    "weak_tls": ("Weak or obsolete TLS settings",
        "Old protocols, short keys or weak hashes make intercepting or forging the connection easier.",
        "Disable old protocols (below TLS 1.2), use 2048-bit RSA or better, and SHA-256 or stronger signatures."),
    "new_certificate": ("Certificate issued very recently",
        "Alone this is harmless, but throwaway phishing sites often use brand-new certificates.",
        "No fix needed for a genuine new site. Visitors should weigh it together with other findings."),
}

# missing security header (label prefix) -> (impact, remediation)
HEADER_CATALOG = {
    "Strict-Transport-Security": ("Browsers may connect over plain http first, allowing downgrade attacks.", "Send Strict-Transport-Security with a long max-age."),
    "Content-Security-Policy": ("Injected script has fewer limits, which makes cross-site scripting worse.", "Define a Content-Security-Policy that limits where scripts and frames come from."),
    "X-Content-Type-Options": ("Browsers may guess file types and run content that was not meant to be script.", "Send X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("Full page addresses may leak to other sites.", "Send a Referrer-Policy such as strict-origin-when-cross-origin."),
    "Clickjacking protection": ("The page can be framed by another site and used to trick clicks.", "Send X-Frame-Options or a CSP frame-ancestors rule."),
    "Served over HTTPS": ("Everything the visitor sends or receives can be read or changed in transit.", "Serve the whole site over HTTPS and redirect http to https."),
    "Cookies use the Secure flag": ("Cookies may travel unencrypted.", "Add the Secure attribute to cookies."),
}


def _evidence(r: Dict[str, Any]) -> str:
    d = r.get("details") or {}
    bits = []
    for k, v in d.items():
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        bits.append(f"{k}: {v}")
    return "; ".join(bits)[:300] or r.get("message", "")


def enrich(reasons: List[Dict[str, Any]], scope: str) -> List[Dict[str, Any]]:
    """Add the report fields in place; existing keys (code, message, severity, details, source) are untouched."""
    limit = CERT_LIMIT if scope == "certificate" else PAGE_LIMIT
    for r in reasons:
        issue, impact, fix = CATALOG.get(r.get("code"), (r.get("message", ""), "Reduces trust in this site.", "Review and correct this finding."))
        r.setdefault("issue", issue)
        r.setdefault("evidence", _evidence(r))
        r.setdefault("impact", impact)
        r.setdefault("remediation", fix)
        r.setdefault("limitations", limit)
    return reasons


def enrich_checks(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Header/cookie/HTTPS checks: each failed check becomes a full finding (ok:true ones are left alone)."""
    for c in checks:
        if c.get("ok"):
            continue
        name = c.get("name", "")
        key = next((k for k in HEADER_CATALOG if name.startswith(k)), None)
        impact, fix = HEADER_CATALOG.get(key, ("Weakens the page's defences.", "Add the missing protection."))
        severity = "medium" if key in ("Strict-Transport-Security", "Content-Security-Policy", "Served over HTTPS") else "low"
        c.update(issue="Missing: " + name, evidence=f"{name}: not present in the response", impact=impact,
                 severity=severity, remediation=fix, limitations=PAGE_LIMIT)
    return checks
