"""Pillar 2: web security assessment (headers, cookies, page content).

Fetches the page once through the SSRF guard WITHOUT executing any script, then
analyses HTML as text. The page is hostile input: the body is capped and parsed
with the stdlib parser only.
"""

from __future__ import annotations

import re
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from .heuristics import BRANDS, is_official
from .netguard import Blocked, resolve_info
from .schema import reason
from .urlparts import host_of, registrable

MAX_BODY = 300_000
TIMEOUT = 8
UA = "Olfa-Scanner/1.0 (passive; no script execution)"


class _PinnedAdapter(HTTPAdapter):
    """Connect to a pre-validated IP while keeping the hostname for SNI and cert checks."""

    def __init__(self, hostname: str, verify: bool, **kw: Any):
        self._hostname, self._verify = hostname, verify
        super().__init__(**kw)

    def init_poolmanager(self, *a: Any, **kw: Any) -> None:
        kw["server_hostname"] = self._hostname
        kw["assert_hostname"] = self._hostname if self._verify else False
        super().init_poolmanager(*a, **kw)


def fetch(url: str, *, allow_private: bool = False) -> Dict[str, Any]:
    """GET one page (no redirects), connecting only to the IP we validated."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    res: Dict[str, Any] = {"url": url, "status": None, "headers": {}, "cookies": [], "body": "", "error": None, "verify_failed": False}
    try:
        ips, via = resolve_info(host, port, allow_private)
        ip = ips[0]
        res["resolved_via"] = via
    except Blocked as exc:
        res["error"] = str(exc)
        return res
    ip_host = f"[{ip}]" if ":" in ip else ip
    pinned = parts._replace(netloc=f"{ip_host}:{port}").geturl()
    headers = {"user-agent": UA, "accept": "text/html,*/*;q=0.5", "host": host if parts.port is None else f"{host}:{port}"}
    for verify in (True, False):
        sess = requests.Session()
        sess.trust_env = False  # ignore proxy env vars: connect exactly where we validated
        sess.mount("https://", _PinnedAdapter(host, verify))
        try:
            with sess.get(pinned, headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True, verify=verify) as r:
                body = b""
                for chunk in r.iter_content(8192):
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                res.update(status=r.status_code, headers={k.lower(): v for k, v in r.headers.items()},
                           body=body.decode(r.encoding or "utf-8", "replace"), verify_failed=not verify)
                raw = getattr(r.raw, "headers", None)
                res["cookies"] = raw.getlist("Set-Cookie") if raw is not None and hasattr(raw, "getlist") else []
                return res
        except requests.exceptions.SSLError:
            if not verify:
                break
            continue  # retry unverified only to inspect the page; the certificate pillar reports the failure
        except requests.RequestException as exc:
            res["error"] = f"{type(exc).__name__}: {exc}"
            return res
    res["error"] = res["error"] or "ssl_error"
    return res


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: List[Dict[str, Any]] = []
        self._form: Optional[Dict[str, Any]] = None
        self.iframes: List[Dict[str, str]] = []
        self.scripts: List[str] = []
        self._script = False
        self.meta_refresh: Optional[str] = None
        self.links_out = 0
        self.links: List[str] = []
        self.text_bits: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "password": False, "inputs": 0}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"] += 1
            if a.get("type", "").lower() == "password":
                self._form["password"] = True
        elif tag == "iframe":
            self.iframes.append(a)
        elif tag in ("a", "area") and a.get("href"):
            self.links.append(a["href"].strip()[:500])
            self.links_out += 1
        elif tag == "script":
            self._script = True
            self.scripts.append("")
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None
        elif tag == "script":
            self._script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif self._script and self.scripts:
            self.scripts[-1] += data
        elif len(self.text_bits) < 400:
            self.text_bits.append(data)


_HIDDEN = re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])|width\s*:\s*0|height\s*:\s*0)", re.I)
_OBFUSCATION = [
    (re.compile(r"eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)", re.I), "eval of decoded string"),
    (re.compile(r"(?:\\x[0-9a-f]{2}){12,}", re.I), "long hex-escaped string"),
    (re.compile(r"String\.fromCharCode\s*\((?:\s*\d+\s*,){15,}", re.I), "character-code string builder"),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.I), "document.write(unescape())"),
]
_URGENT = re.compile(r"(account.{0,25}(suspend|lock|limited|closed)|verify.{0,25}(immediately|now|within)|urgent|unusual (sign.?in|activity)|your .{0,20}will be (closed|blocked|deactivated))", re.I)
_SEC_HEADERS = [
    ("strict-transport-security", "HSTS (forces https)"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
]


def _grade(points_lost: int) -> str:
    return "A" if points_lost <= 1 else "B" if points_lost <= 3 else "C" if points_lost <= 5 else "D" if points_lost <= 7 else "F"


def assess(page: Dict[str, Any], final_url: str) -> Dict[str, Any]:
    """Return {"web": {...}, "reasons": [...]} from a fetched page."""
    reasons: List[dict] = []
    host = host_of(final_url)
    reg = registrable(host)
    web: Dict[str, Any] = {"status": page.get("status"), "fetched": page.get("status") is not None,
                           "error": page.get("error"), "headers": {}, "forms": [], "grade": None, "checks": []}
    if page.get("status") is None:
        return {"web": web, "reasons": reasons}

    hdr = page["headers"]
    https = urlsplit(final_url).scheme == "https"
    lost = 0
    checks = web["checks"]
    for key, label in _SEC_HEADERS:
        present = key in hdr
        if key == "strict-transport-security" and not https:
            continue
        checks.append({"name": label, "ok": present})
        if not present:
            lost += 2 if key in ("strict-transport-security", "content-security-policy") else 1
    framed = "x-frame-options" in hdr or "frame-ancestors" in hdr.get("content-security-policy", "")
    checks.append({"name": "Clickjacking protection (X-Frame-Options / frame-ancestors)", "ok": framed})
    lost += 0 if framed else 1
    checks.append({"name": "Served over HTTPS", "ok": https})
    if not https:
        lost += 3
    web["headers"] = {k: hdr[k] for k in ("server", "x-powered-by", "strict-transport-security", "content-security-policy",
                                          "x-frame-options", "x-content-type-options", "referrer-policy") if k in hdr}

    # cookies
    bad_cookies = []
    for c in page.get("cookies", []):
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        flags = {"secure": "secure" in low, "httponly": "httponly" in low, "samesite": "samesite" in low}
        if https and not flags["secure"]:
            bad_cookies.append(name)
    if bad_cookies:
        lost += 1
        reasons.append(reason("cookies_missing_secure", f"{len(bad_cookies)} cookie(s) are set without the Secure flag.", "low", {"cookies": bad_cookies[:5]}, "web"))
    checks.append({"name": "Cookies use the Secure flag", "ok": not bad_cookies})
    web["grade"] = _grade(lost)
    web["score"] = max(0, 100 - lost * 10)

    # content
    body = page.get("body", "")
    p = _Page()
    try:
        p.feed(body)
    except Exception:  # noqa: BLE001 - malformed hostile HTML must never crash a scan
        pass
    web["title"] = p.title.strip()[:120]

    for f in p.forms:
        target = urljoin(final_url, f["action"]) if f["action"] else final_url
        t_host = host_of(target)
        cross = bool(t_host) and registrable(t_host) != reg
        entry = {"action": target, "has_password": f["password"], "cross_origin": cross, "method": f["method"]}
        web["forms"].append(entry)
        if f["password"]:
            if cross:
                reasons.append(reason("credential_form_cross_origin", f"The login form sends your password to a different site ({registrable(t_host)}).", "high", {"action": target}, "web"))
            if urlsplit(target).scheme == "http":
                reasons.append(reason("credentials_over_http", "The login form sends your password without encryption.", "high", {"action": target}, "web"))

    for fr in p.iframes:
        style = fr.get("style", "")
        tiny = fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1")
        if _HIDDEN.search(style) or tiny or "hidden" in fr:
            src = urljoin(final_url, fr.get("src", ""))
            if src and registrable(host_of(src)) != reg:
                reasons.append(reason("hidden_iframe", "The page embeds a hidden frame from another site.", "high", {"src": src}, "web"))
                break
    code = "\n".join(p.scripts)
    for rx, label in _OBFUSCATION:
        if rx.search(code):
            reasons.append(reason("obfuscated_script", f"The page runs obfuscated script ({label}).", "medium", {"technique": label}, "web"))
            break

    # link targets: `#` / javascript:void(0) placeholders, and javascript: links that move the browser
    hrefs = [h.strip() for h in p.links]
    js_payload = [h for h in hrefs if h.lower().startswith("javascript:")
                  and re.search(r"(https?:|document\.location|window\.location|location\.href\s*=|location\s*=)", h, re.I)]
    stubs = [h for h in hrefs if h.lower().rstrip("; ") in ("#", "#_", "javascript:void(0)", "javascript:return false")]
    web["link_targets"] = {"total": len(hrefs), "js_payload": len(js_payload), "stubs": len(stubs)}
    if js_payload:
        reasons.append(reason("javascript_link_payload",
                              f"{len(js_payload)} link(s) hide their destination inside javascript: code, which can send you somewhere else.",
                              "medium", {"sample": js_payload[:2]}, "web"))
    if len(hrefs) >= 8 and len(stubs) * 10 // len(hrefs) >= 4:
        reasons.append(reason("hidden_link_targets",
                              f"{len(stubs)} of {len(hrefs)} links are placeholders ('#' or javascript:void(0)), so their real targets are hidden in script.",
                              "low", {"stubs": len(stubs), "total": len(hrefs)}, "web"))
    text = (p.title + " " + " ".join(p.text_bits))[:20000]
    if _URGENT.search(text):
        reasons.append(reason("urgency_language", "The page uses pressure language such as 'verify immediately' or 'account suspended'.", "low", {}, "web"))
    if p.meta_refresh and re.search(r"url\s*=", p.meta_refresh, re.I):
        web["meta_refresh"] = p.meta_refresh[:200]

    # brand named in title/body but page is not on that brand's domain, and it asks for a password
    if any(f["password"] for f in p.forms) and not is_official(host):
        title_l = (p.title + " " + text[:3000]).lower()
        for brand, doms in BRANDS.items():
            if re.search(r"\b" + re.escape(brand) + r"\b", title_l) and reg not in doms:
                reasons.append(reason("brand_impersonation", f"A login page for {brand} is hosted on '{reg}', not on {brand}'s own domain.", "high", {"brand": brand, "domain": reg}, "web"))
                break
    return {"web": web, "reasons": reasons}


def check(final_url: str, *, allow_private: bool = False) -> Dict[str, Any]:
    page = fetch(final_url, allow_private=allow_private)
    out = assess(page, final_url)
    out["page"] = page
    return out
