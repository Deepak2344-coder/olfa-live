"""Small outbound HTTP helper that goes through the SSRF guard (netguard).

Resolves the host itself, refuses non-public addresses, connects to that IP with the real hostname
for TLS checks, ignores proxy env vars, never follows redirects and caps the response size.
Returns {"status", "body", "error"}; it never raises, so callers can report "not run".
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import requests

from .netguard import Blocked, resolve_info
from .webcheck import _PinnedAdapter

MAX_BYTES = 200_000


def request(method: str, url: str, *, json_body: Optional[dict] = None, data: Optional[dict] = None,
            headers: Optional[Dict[str, str]] = None, timeout: float = 8.0, allow_private: bool = False,
            max_bytes: int = MAX_BYTES) -> Dict[str, Any]:
    res: Dict[str, Any] = {"status": None, "body": "", "error": None}
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https" or not host:
        res["error"] = "only https URLs are allowed"
        return res
    port = parts.port or 443
    try:
        ips, _ = resolve_info(host, port, allow_private)
    except Blocked as exc:
        res["error"] = f"blocked: {exc}"
        return res
    ip = ips[0]
    ip_host = f"[{ip}]" if ":" in ip else ip
    pinned = parts._replace(netloc=f"{ip_host}:{port}").geturl()
    hdr = {"host": host, "user-agent": "Olfa/1.0"}
    hdr.update(headers or {})
    sess = requests.Session()
    sess.trust_env = False
    sess.mount("https://", _PinnedAdapter(host, True))
    try:
        with sess.request(method, pinned, headers=hdr, json=json_body, data=data, timeout=timeout, allow_redirects=False,
                          stream=True, verify=True) as r:
            body = b""
            for chunk in r.iter_content(8192):
                body += chunk
                if len(body) >= max_bytes:
                    break
            res.update(status=r.status_code, body=body.decode(r.encoding or "utf-8", "replace"))
    except requests.RequestException as exc:
        res["error"] = type(exc).__name__
    return res


def post_json(url: str, payload: dict, **kw: Any) -> Dict[str, Any]:
    out = request("POST", url, json_body=payload, **kw)
    try:
        out["json"] = json.loads(out["body"]) if out["body"] else None
    except ValueError:
        out["json"] = None
    return out
