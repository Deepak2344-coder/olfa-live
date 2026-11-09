"""Known-threat feeds behind one small interface.

OpenPhish's community feed needs no key. URLhaus (abuse.ch) is added only when URLHAUS_AUTH_KEY is set in
the environment (never log or print it). Feeds are cached, use short timeouts and the SSRF guard. If a feed is
unavailable the result says "not checked"; it is never counted as clean.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from . import guarded_http
from .popular import is_popular
from .schema import reason
from .urlparts import host_of, registrable

FEED_TTL = 6 * 3600       # re-download the list every 6 hours
FAIL_TTL = 300            # after a failed download, wait 5 minutes before retrying
RESULT_TTL = 600


def _key(url: str) -> str:
    p = urlsplit(url if "://" in url else "http://" + url)
    return (p.hostname or "").lower() + (p.path.rstrip("/") or "") + (("?" + p.query) if p.query else "")


class Feed:
    name = "feed"

    def lookup(self, url: str) -> Dict[str, Any]:
        """{"status": "ok"|"not_checked", "matches": [{"kind": "url"|"host", "detail": str}], "error": str|None}"""
        raise NotImplementedError


class OpenPhishFeed(Feed):
    name = "OpenPhish"
    URL = "https://openphish.com/feed.txt"

    def __init__(self) -> None:
        self._urls: set = set()
        self._hosts: set = set()
        self._loaded = 0.0
        self._failed = 0.0

    def _refresh(self) -> bool:
        now = time.time()
        if self._loaded and now - self._loaded < FEED_TTL:
            return True
        if self._failed and now - self._failed < FAIL_TTL:
            return bool(self._loaded)  # keep serving a stale list if we have one
        r = guarded_http.request("GET", self.URL, timeout=6, max_bytes=5_000_000)
        if r.get("status") != 200 or not r.get("body"):
            self._failed = now
            return bool(self._loaded)
        lines = [l.strip() for l in r["body"].splitlines() if l.strip().startswith("http")]
        self._urls = {_key(l) for l in lines}
        self._hosts = {host_of(l) for l in lines if host_of(l)}
        self._loaded, self._failed = now, 0.0
        return True

    def lookup(self, url: str) -> Dict[str, Any]:
        if not self._refresh():
            return {"status": "not_checked", "matches": [], "error": "feed unavailable"}
        matches: List[Dict[str, str]] = []
        if _key(url) in self._urls:
            matches.append({"kind": "url", "detail": "This exact address is listed in the OpenPhish phishing feed."})
        else:
            host = host_of(url)
            if host in self._hosts and not is_popular(registrable(host)):
                matches.append({"kind": "host", "detail": "Another address on this host is listed in the OpenPhish phishing feed."})
        return {"status": "ok", "matches": matches, "error": None}


class UrlhausFeed(Feed):
    name = "URLhaus"
    API = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, auth_key: str) -> None:
        self._key = auth_key

    def lookup(self, url: str) -> Dict[str, Any]:
        r = guarded_http.request("POST", self.API, data={"url": url}, headers={"Auth-Key": self._key}, timeout=5)
        if r.get("status") != 200:
            return {"status": "not_checked", "matches": [], "error": "feed unavailable"}
        try:
            j = json.loads(r["body"])
        except (ValueError, TypeError):
            return {"status": "not_checked", "matches": [], "error": "bad response"}
        if j.get("query_status") == "ok":
            return {"status": "ok", "error": None, "matches": [{"kind": "url", "detail": f"URLhaus lists this address ({j.get('threat') or 'malicious'}, {j.get('url_status') or 'status unknown'})."}]}
        if j.get("query_status") == "no_results":
            return {"status": "ok", "matches": [], "error": None}
        return {"status": "not_checked", "matches": [], "error": "unexpected response"}


_default: Optional[List[Feed]] = None
_results: Dict[str, tuple] = {}


def default_feeds() -> List[Feed]:
    global _default
    if _default is None:
        _default = [OpenPhishFeed()]
        key = os.environ.get("URLHAUS_AUTH_KEY", "")
        if key:
            _default.append(UrlhausFeed(key))
    return _default


def check(urls: List[str], feeds: Optional[List[Feed]] = None) -> Dict[str, Any]:
    """Look up each URL in each feed. Returns {"status", "matches", "sources", "line", "reasons"}."""
    feeds = default_feeds() if feeds is None else feeds
    matches: List[Dict[str, str]] = []
    sources = []
    for f in feeds:
        ok_any, err = False, None
        for u in dict.fromkeys(urls):
            ck = f"{f.name}|{u}"
            hit = _results.get(ck)
            if hit and time.time() - hit[0] < RESULT_TTL:
                res = hit[1]
            else:
                try:
                    res = f.lookup(u)
                except Exception:  # noqa: BLE001 - a feed must never break a scan
                    res = {"status": "not_checked", "matches": [], "error": "lookup failed"}
                if res["status"] == "ok":
                    _results[ck] = (time.time(), res)
                    if len(_results) > 2000:
                        _results.pop(next(iter(_results)))
            if res["status"] == "ok":
                ok_any = True
                matches += [{"source": f.name, "url": u, **m} for m in res["matches"]]
            else:
                err = res.get("error")
        sources.append({"name": f.name, "status": "ok" if ok_any else "not_checked", "error": None if ok_any else err})
    checked = [s for s in sources if s["status"] == "ok"]
    status = "ok" if sources and len(checked) == len(sources) else "partial" if checked else "not_checked"
    names = ", ".join(sorted({m["source"] for m in matches}))
    if matches:
        line = f"Known threat intelligence matches: {len(matches)} ({names})"
    elif status == "ok":
        line = "Known threat intelligence matches: none found in " + ", ".join(s["name"] for s in sources)
    elif status == "partial":
        line = ("Known threat intelligence matches: none found in " + ", ".join(s["name"] for s in checked)
                + "; not checked: " + ", ".join(s["name"] for s in sources if s["status"] != "ok"))
    else:
        line = "Known threat intelligence matches: not checked (feeds unavailable)"
    reasons = []
    seen = set()
    for m in matches:
        k = (m["source"], m["kind"])
        if k in seen:
            continue
        seen.add(k)
        high = m["kind"] == "url"
        reasons.append(reason("threat_feed_match", m["detail"], "high" if high else "medium",
                              {"feed": m["source"], "match": m["kind"]}, "feed"))
    return {"status": status, "matches": matches, "sources": sources, "line": line, "reasons": reasons}
