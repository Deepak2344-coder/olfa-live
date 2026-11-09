"""SSRF guard shared by every module that touches the network.

Olfa fetches attacker-chosen URLs, so each connection goes only to a public IP
that we resolved and validated ourselves (no second DNS lookup -> no rebinding).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import List, Optional, Tuple


class Blocked(Exception):
    pass


def extra_allowed_networks() -> list:
    """Opt-in escape hatch for networks where DNS legitimately returns non-public
    addresses (VPN/proxy 'fake-IP' mode uses 198.18.0.0/15). Off by default.
    Example: OLFA_ALLOW_CIDRS=198.18.0.0/15"""
    nets = []
    for part in os.environ.get("OLFA_ALLOW_CIDRS", "").split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return nets


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(a in n for n in extra_allowed_networks()):
        return True
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified)


_DOH = ("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve")
_doh_cache: dict = {}


def _doh_lookup(host: str) -> List[str]:
    """Ask a public DNS-over-HTTPS resolver for A records (IP-literal endpoints, no system DNS involved).
    Disable with OLFA_DOH=0."""
    import time
    if os.environ.get("OLFA_DOH", "1") == "0":
        return []
    hit = _doh_cache.get(host)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    import requests
    ips: List[str] = []
    for endpoint in _DOH:
        try:
            r = requests.get(endpoint, params={"name": host, "type": "A"}, headers={"accept": "application/dns-json"}, timeout=3)
            ips = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
            if ips:
                break
        except Exception:  # noqa: BLE001 - try the next resolver
            continue
    _doh_cache[host] = (time.time(), ips)
    return ips


def resolve_info(host: str, port: int, allow_private: bool = False) -> Tuple[List[str], str]:
    """Return (addresses, via) where via is "system" or "doh". Raises Blocked.

    Every address we return is public (unless allow_private, tests only), so
    callers can connect to it directly: no second lookup, no DNS rebinding.
    If the system resolver answers with a private address (VPN fake-IP mode,
    filtering DNS), a public resolver gets one chance; its answers must ALL be
    public too, so a name that really points inside a network stays blocked."""
    try:
        sys_ips = sorted({i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except socket.gaierror:
        sys_ips = []
    if sys_ips and (allow_private or all(is_public(ip) for ip in sys_ips)):
        return sys_ips, "system"
    is_literal = bool(sys_ips) and sys_ips == [host.strip("[]")]
    if not is_literal and not allow_private:
        doh = _doh_lookup(host)
        if doh and all(is_public(ip) for ip in doh):
            return sorted(doh), "doh"
    if not sys_ips:
        raise Blocked("dns_failed: no addresses")
    raise Blocked("private_address: " + ", ".join(ip for ip in sys_ips if not is_public(ip)))


def resolve_public(host: str, port: int, allow_private: bool = False) -> List[str]:
    return resolve_info(host, port, allow_private)[0]
