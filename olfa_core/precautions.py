"""Deterministic 'what you should do' advice built from the verdict and reason codes (no AI)."""

from __future__ import annotations

from typing import Any, Dict, List

SAFE_TIPS = [
    "No warning signs were found, but no scan is a guarantee. Check the address bar before you type a password.",
    "Turn on two-factor authentication for important accounts so a stolen password alone is not enough.",
]

BASE_TIPS = {
    "suspicious": [
        "Do not enter passwords, card numbers or one-time codes on this page until you have checked it.",
        "Open the real site by typing its address yourself or using your bookmark, not this link.",
        "Report the link to the people who sent it or to your IT or security team if it came through work.",
    ],
    "dangerous": [
        "Do not open this link. If you already did, do not enter any password, card number or code.",
        "Do not download or run any file from this site.",
        "Verify the address on the real brand's own website or app before you trust anything it claims.",
        "Report it here in the Community tab and to the service it imitates, then delete the message.",
    ],
}

# code (optionally code:detail) -> tip, only shown for suspicious/dangerous verdicts
REASON_TIPS = {
    "brand_impersonation": "This address imitates a known brand. Go to that brand's real site by typing its address yourself.",
    "typosquat": "The domain is a near-copy of a well-known name. Compare it letter by letter with the real address.",
    "credential_form_cross_origin": "A login form on this page sends data to a different site. Never type a password here.",
    "credentials_over_http": "Passwords would travel unencrypted. Do not sign in on this page.",
    "credential_words": "The page asks for sign-in details. Only sign in at the address you know is genuine.",
    "no_https": "The connection is not encrypted. Do not enter personal or payment details.",
    "bad_certificate": "The security certificate failed validation. Leave the page and do not click through the browser warning.",
    "cert_expired": "The security certificate has expired. Do not enter personal details here.",
    "cert_hostname_mismatch": "The certificate belongs to a different site name. Treat the page as untrustworthy.",
    "self_signed_certificate": "The certificate is self-issued, so nobody independent vouches for this site.",
    "new_certificate": "The certificate was issued very recently, which is common for throwaway phishing sites.",
    "new_domain": "The domain was registered very recently. Be extra careful with sites that are only days old.",
    "punycode_domain": "The address uses look-alike characters. Retype the real address yourself instead of clicking.",
    "ip_address_host": "The link points to a raw IP address instead of a name. Legitimate services rarely do this.",
    "suspicious_url_pattern": "The address is built to hide its real destination. Do not trust the visible part of it.",
    "urgency_language": "The page pressures you to act fast. Slow down: genuine services rarely demand instant action.",
    "hidden_iframe": "The page hides embedded content. Close the tab and do not interact with it.",
    "obfuscated_script": "The page runs disguised code. Close it and do not download anything from it.",
    "javascript_link_payload": "Links on the page run hidden code. Do not click anything on it.",
    "shortener_used": "A link shortener hides the real address. Ask the sender for the full link.",
    "domain_hopping": "The link passes through several unrelated domains. Do not continue.",
    "final_domain_differs_from_origin": "The link lands somewhere other than where it started. Check the final address before trusting it.",
    "https_downgrade": "The link drops from secure to plain http. Do not enter any details.",
    "threat_feed_match": "This address appears in a public list of known threats. Do not open it or enter anything.",
    "new_nameserver": "The site's DNS is run by a very new provider domain, which is typical of throwaway sites.",
    "no_mail_records": "The domain imitates a brand but cannot send or receive real email. Ignore messages from it.",
    "community_confirmed": "Several community reporters confirmed this site as malicious. Stay away from it.",
    "community_reported": "Community members have reported this site. Wait for confirmation before trusting it.",
}


def build(level: str, reasons: List[Dict[str, Any]]) -> List[str]:
    """Return a non-empty, de-duplicated list of tips for a scan result."""
    if level not in BASE_TIPS:
        return list(SAFE_TIPS)
    tips: List[str] = []
    seen = set()
    for r in sorted(reasons or [], key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("severity"), 3)):
        tip = REASON_TIPS.get(r.get("code"))
        if tip and tip not in seen:
            seen.add(tip)
            tips.append(tip)
    tips = tips[:4]
    return tips + [t for t in BASE_TIPS[level] if t not in seen]
