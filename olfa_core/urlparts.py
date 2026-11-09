"""URL normalisation helpers shared by every pillar."""

from __future__ import annotations

import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlsplit

import tldextract

# Offline: use the suffix-list snapshot bundled with tldextract, never fetch.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def normalize_url(raw: str) -> str:
    """Add a scheme when missing and strip whitespace. Raises ValueError on junk."""
    url = (raw or "").strip()
    if not url or len(url) > 4096 or any(c in url for c in "\r\n\t "):
        raise ValueError("empty, too long, or contains whitespace")
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("only http(s) URLs with a host are supported")
    return url


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def port_of(url: str) -> Optional[int]:
    try:
        return urlsplit(url).port
    except ValueError:
        return None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def split_domain(host: str) -> Tuple[str, str, str]:
    """(subdomain, registrable_domain, suffix). IPs return ('', host, '')."""
    if is_ip(host):
        return "", host, ""
    ext = _extract(host)
    registrable = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return ext.subdomain, registrable or host, ext.suffix


def registrable(host: str) -> str:
    return split_domain(host)[1]
