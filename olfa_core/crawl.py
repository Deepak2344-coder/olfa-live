"""One crawler for redirects + the final page.

Replaces features/redirect-tracer's fetch loop (its flag rules, shortener list and
meta/JS-redirect detection are reused). Why: the tracer checked an address once and
then let `requests` look the name up again, so it could connect somewhere else than
it validated. Every hop here goes through webcheck.fetch, which connects only to the
address netguard validated, and the final hop's page is kept so the page-security
check does not fetch it a second time.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin

from . import webcheck
from .scanner_tracer import tracer
from .urlparts import host_of, registrable


def _site(url: str) -> str:
    """Registrable domain of a URL: 'www.amazon.in' and 'amazon.in' are one site."""
    return registrable(host_of(url))


def drop_same_site_flags(flags, hops, origin, final_url):
    """The tracer compares raw hosts, so `amazon.in -> www.amazon.in` (the most
    common redirect on the web) was reported as domain_hopping AND as landing on
    a different domain. Both are only interesting when the registrable domains
    really differ; everything else (shorteners, downgrades, loops) is kept."""
    out = list(flags)
    if len({_site(str(h.get("url", ""))) for h in hops}) <= 1:
        out = [f for f in out if f != "domain_hopping"]
    if _site(final_url) == _site(origin):
        out = [f for f in out if f != "final_domain_differs_from_origin"]
    return out


def crawl(url: str, *, allow_private: bool = False, max_hops: int = 10) -> Dict[str, Any]:
    hops, flags = [], []
    seen: set = set()
    current, prev_site = url, _site(url)
    final_url, final_page, error, via = url, None, None, None
    for _ in range(max_hops + 1):
        if current in seen:
            hops.append(tracer.Hop(url=current, note="already visited", kind="loop"))
            flags.append("redirect_loop")
            break
        seen.add(current)
        domain = tracer.host_of(current)
        site = _site(current)
        hop = tracer.Hop(url=current, domain=domain, shortener=tracer.is_shortener(current), domain_changed=site != prev_site)
        prev_site = site
        t0 = time.perf_counter()
        page = webcheck.fetch(current, allow_private=allow_private)
        hop.elapsed_ms = int((time.perf_counter() - t0) * 1000)
        via = via or page.get("resolved_via")
        if page["status"] is None:
            err = str(page.get("error") or "fetch failed")
            if err.startswith("private_address"):
                ip = err.split(":", 1)[1].strip()
                hop.kind, hop.error = "blocked", f"blocked a private address ({domain} -> {ip})"
            else:
                hop.error = err
            hops.append(hop)
            error = hop.error
            break
        hop.status = page["status"]
        loc = page["headers"].get("location")
        if 300 <= page["status"] < 400 and loc:
            hops.append(hop)
            current = urljoin(current, loc)
            continue
        target, kind = tracer._next_from_body(page["body"], current)
        if target:
            hop.kind = kind
            hops.append(hop)
            current = target
            continue
        hops.append(hop)
        final_url, final_page = current, page
        break
    else:
        final_url = current
    if len(hops) > max_hops:
        flags.append("too_many_hops")
    hop_dicts = [h.as_dict() for h in hops]
    flags.extend(tracer.compute_flags(hop_dicts, url, final_url))
    flags = drop_same_site_flags(list(dict.fromkeys(flags)), hop_dicts, url, final_url)
    return {"origin": url, "final_url": final_url, "hops": hop_dicts, "flags": flags,
            "error": error, "final_page": final_page, "resolved_via": via}
