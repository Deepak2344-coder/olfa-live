"""Follow a URL's redirect chain safely.

Pure standard library + requests. Two halves:

* :func:`trace` performs the network walk (http(s), 3xx, meta-refresh and a
  conservative JS `location` regex), with a hop cap, per-hop timeout and an
  SSRF guard that refuses private/loopback/link-local destinations.
* :func:`compute_flags` turns the hop list into the flags the UI shows. It is
  pure, so the interesting rules are unit tested without a network.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

MAX_HOPS = 10
HOP_TIMEOUT = 6
MAX_BODY_BYTES = 200_000

_HERE = __import__("pathlib").Path(__file__).parent

# Redirects a browser would follow via markup rather than a 3xx header.
META_REFRESH_RE = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*content\s*=\s*['\"][^'\"]*url\s*=\s*([^'\">\s]+)",
    re.IGNORECASE,
)
# Only literal assignments; we never execute page code.
JS_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['\"]([^'\"\s]+)['\"]",
    re.IGNORECASE,
)


def load_shorteners() -> Set[str]:
    with open(_HERE / "shorteners.json", "r", encoding="utf-8") as handle:
        return {entry.lower() for entry in json.load(handle)["domains"]}


SHORTENERS = load_shorteners()


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_shortener(url: str) -> bool:
    host = host_of(url)
    return any(host == domain or host.endswith("." + domain) for domain in SHORTENERS)


def _is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def check_url(url: str, allow_private: bool = False, allow_hosts: Iterable[str] = ()) -> Optional[str]:
    """Return an error string when ``url`` must not be fetched, else None."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "only http and https URLs can be traced"
    host = (parsed.hostname or "").lower()
    if not host:
        return "the URL has no host"
    if allow_private:
        return None
    if host in {h.lower() for h in allow_hosts}:
        return None
    if host == "localhost":
        return "blocked a private address (localhost)"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return f"could not resolve {host}"
    for info in infos:
        if _is_private_ip(info[4][0]):
            return f"blocked a private address ({host} -> {info[4][0]})"
    return None


@dataclass
class Hop:
    url: str
    status: Optional[int] = None
    domain: str = ""
    kind: str = "http"  # http | meta_refresh | js
    shortener: bool = False
    domain_changed: bool = False
    elapsed_ms: int = 0
    error: Optional[str] = None
    note: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "status": self.status,
            "domain": self.domain or host_of(self.url),
            "kind": self.kind,
            "shortener": self.shortener,
            "domain_changed": self.domain_changed,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "note": self.note,
        }


@dataclass
class TraceResult:
    origin: str
    hops: List[Hop] = field(default_factory=list)
    final_url: str = ""
    flags: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "origin": self.origin,
            "final_url": self.final_url or self.origin,
            "hops": [hop.as_dict() for hop in self.hops],
            "flags": self.flags,
            "error": self.error,
        }


def _next_from_body(body: str, base: str) -> Tuple[Optional[str], str]:
    """Find a meta-refresh or literal JS redirect in an HTML body."""
    match = META_REFRESH_RE.search(body)
    if match:
        return urljoin(base, match.group(1)), "meta_refresh"
    match = JS_REDIRECT_RE.search(body)
    if match:
        candidate = match.group(1)
        if candidate.startswith(("http://", "https://", "/")):
            return urljoin(base, candidate), "js"
    return None, ""


def trace(
    url: str,
    *,
    max_hops: int = MAX_HOPS,
    timeout: int = HOP_TIMEOUT,
    allow_private: bool = False,
    allow_hosts: Sequence[str] = (),
    session: Optional[requests.Session] = None,
) -> TraceResult:
    """Walk ``url``'s redirect chain. Never raises: failures become ``error``."""
    result = TraceResult(origin=url)
    current = url
    seen = set()
    http = session or requests.Session()
    http.headers.update({"user-agent": "Olfa-RedirectTracer/1.0 (+passive)"})

    previous_domain = host_of(url)

    for _ in range(max_hops + 1):
        if current in seen:
            result.flags.append("redirect_loop")
            result.hops.append(Hop(url=current, note="already visited", kind="loop"))
            break
        seen.add(current)

        refusal = check_url(current, allow_private=allow_private, allow_hosts=allow_hosts)
        if refusal:
            result.hops.append(Hop(url=current, error=refusal, kind="blocked"))
            result.flags.append("blocked_private_address")
            result.error = refusal
            break

        domain = host_of(current)
        hop = Hop(url=current, domain=domain, shortener=is_shortener(current), domain_changed=domain != previous_domain)
        previous_domain = domain
        started = time.perf_counter()

        try:
            response = http.get(current, allow_redirects=False, timeout=timeout, stream=True)
            hop.status = response.status_code
            hop.elapsed_ms = int((time.perf_counter() - started) * 1000)

            if response.is_redirect and response.headers.get("location"):
                target = urljoin(current, response.headers["location"])
                result.hops.append(hop)
                current = target
                continue

            # Not a 3xx: look for markup redirects in the body.
            body = b""
            for chunk in response.iter_content(8192):
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
            response.close()
            text = body.decode(response.encoding or "utf-8", errors="replace")
            target, kind = _next_from_body(text, current)
            if target:
                hop.kind = kind
                result.hops.append(hop)
                current = target
                continue

            result.hops.append(hop)
            result.final_url = current
            break
        except requests.RequestException as exc:
            hop.elapsed_ms = int((time.perf_counter() - started) * 1000)
            hop.error = f"{type(exc).__name__}: {exc}"
            result.hops.append(hop)
            result.error = hop.error
            break

    else:
        # Loop finished without break: we hit the cap.
        result.final_url = current

    if len(result.hops) > max_hops:
        result.flags.append("too_many_hops")

    result.flags.extend(compute_flags([hop.as_dict() for hop in result.hops], result.origin, result.final_url or result.origin))
    # De-duplicate while keeping order.
    result.flags = list(dict.fromkeys(result.flags))
    return result


def compute_flags(hops: Sequence[Dict[str, object]], origin: str, final_url: str, max_hops: int = MAX_HOPS) -> List[str]:
    """Pure flag rules shared by the API, the UI and the tests."""
    flags: List[str] = []
    if len(hops) > max_hops:
        flags.append("too_many_hops")
    if any(hop.get("shortener") for hop in hops):
        flags.append("shortener_used")
    origin_domain = host_of(origin)
    final_domain = host_of(final_url)
    domains = [hop.get("domain") or host_of(str(hop.get("url", ""))) for hop in hops]
    if len({d for d in domains if d}) > 1:
        flags.append("domain_hopping")
    if final_domain and origin_domain and final_domain != origin_domain:
        flags.append("final_domain_differs_from_origin")
    for hop in hops:
        url = str(hop.get("url", ""))
        if urlparse(url).scheme == "https":
            continue
    # https -> http anywhere in the chain is a downgrade.
    schemes = [urlparse(str(hop.get("url", ""))).scheme for hop in hops]
    for previous, current in zip(schemes, schemes[1:]):
        if previous == "https" and current == "http":
            flags.append("https_downgrade")
            break
    if any(hop.get("kind") == "loop" or hop.get("note") == "already visited" for hop in hops):
        if "redirect_loop" not in flags:
            flags.append("redirect_loop")
    if any(hop.get("error") for hop in hops):
        blocked = [hop for hop in hops if hop.get("error")]
        if any("private address" in str(hop.get("error")) for hop in blocked):
            flags.append("blocked_private_address")
        else:
            flags.append("fetch_failed")
    return list(dict.fromkeys(flags))


def risk_score(hops: Sequence[Dict[str, object]], flags: Sequence[str]) -> float:
    """Map flags to the shared 0-1 score. Deliberately gentle: redirects are
    common; only real misbehaviour (private targets, loops, downgrades) counts."""
    weights = {
        "blocked_private_address": 0.9,
        "redirect_loop": 0.6,
        "https_downgrade": 0.5,
        "too_many_hops": 0.35,
        "final_domain_differs_from_origin": 0.2,
        "domain_hopping": 0.15,
        "shortener_used": 0.1,
        "fetch_failed": 0.1,
    }
    score = sum(weights.get(flag, 0.05) for flag in flags)
    if hops:
        score = max(score, 0.02)
    return min(1.0, round(score, 4))
