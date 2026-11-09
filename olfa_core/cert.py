"""Pillar 3: TLS certificate validation.

Two handshakes: one that *verifies* against the system trust store (so we learn
exactly why it fails), and one that does not verify (so we can still inspect the
certificate a phishing site presents).
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from . import findings
from .netguard import Blocked, resolve_info
from .schema import reason

TIMEOUT = 6
WEAK_SIG = {"md5", "sha1"}
_VERIFY_MESSAGES = {
    "self-signed certificate": "self_signed",
    "self signed certificate": "self_signed",
    "certificate has expired": "expired",
    "unable to get local issuer certificate": "untrusted_issuer",
    "unable to get issuer certificate": "untrusted_issuer",
    "Hostname mismatch": "hostname_mismatch",
    "IP address mismatch": "hostname_mismatch",
}


def _name(n: x509.Name) -> Dict[str, str]:
    def first(oid):
        v = n.get_attributes_for_oid(oid)
        return v[0].value if v else ""
    return {"cn": first(NameOID.COMMON_NAME), "org": first(NameOID.ORGANIZATION_NAME), "rfc4514": n.rfc4514_string()}


def _describe(der: bytes) -> Dict[str, Any]:
    c = x509.load_der_x509_certificate(der)
    try:
        sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    try:
        bc = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key = f"RSA-{pk.key_size}"
        key_bits = pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key = f"EC-{pk.curve.name}"
        key_bits = pk.key_size
    else:
        key, key_bits = type(pk).__name__, 0
    not_before = c.not_valid_before_utc
    not_after = c.not_valid_after_utc
    sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "unknown"
    return {
        "subject": _name(c.subject), "issuer": _name(c.issuer), "sans": sans,
        "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
        "self_signed": c.subject == c.issuer, "is_ca": is_ca, "key": key, "key_bits": key_bits,
        "signature_hash": sig, "serial": format(c.serial_number, "x"),
        "sha256": c.fingerprint(hashes.SHA256()).hex(),
        "_nb": not_before, "_na": not_after,
    }


def _host_matches(host: str, sans: List[str], cn: str) -> bool:
    names = sans or ([cn] if cn else [])
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def _connect(ip: str, port: int) -> socket.socket:
    return socket.create_connection((ip, port), timeout=TIMEOUT)


def inspect(host: str, port: int = 443, *, allow_private: bool = False, ca_file: Optional[str] = None) -> Dict[str, Any]:
    """Return raw cert facts. Never raises; failures set `error`."""
    out: Dict[str, Any] = {"host": host, "port": port, "reachable": False, "verified": False,
                           "verify_error": None, "verify_kind": None, "tls_version": None, "cipher": None,
                           "chain": [], "leaf": None, "error": None}
    try:
        ips, via = resolve_info(host, port, allow_private)
        ip = ips[0]
        out["resolved_via"] = via
    except Blocked as exc:
        out["error"] = str(exc)
        return out

    # 1) verifying handshake
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    try:
        with _connect(ip, port) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            out.update(reachable=True, verified=True, tls_version=s.version(), cipher=(s.cipher() or [None])[0])
    except ssl.SSLCertVerificationError as exc:
        out.update(reachable=True, verify_error=exc.verify_message or str(exc))
        out["verify_kind"] = next((k for m, k in _VERIFY_MESSAGES.items() if m.lower() in (exc.verify_message or "").lower()), "invalid")
    except (ssl.SSLError, OSError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    # 2) inspecting handshake (no verification) to read what was presented
    ictx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ictx.check_hostname = False
    ictx.verify_mode = ssl.CERT_NONE
    ictx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    try:
        with _connect(ip, port) as raw, ictx.wrap_socket(raw, server_hostname=host) as s:
            out["reachable"] = True
            out["tls_version"] = out["tls_version"] or s.version()
            out["cipher"] = out["cipher"] or (s.cipher() or [None])[0]
            leaf_der = s.getpeercert(binary_form=True)
            chain_ders: List[bytes] = []
            getter = getattr(s, "get_unverified_chain", None)
            if getter:
                try:
                    chain_ders = [c if isinstance(c, bytes) else ssl.PEM_cert_to_DER_cert(c.public_bytes()) if hasattr(c, "public_bytes") else bytes(c)
                                  for c in getter()]
                except Exception:  # noqa: BLE001
                    chain_ders = []
            if leaf_der and not chain_ders:
                chain_ders = [leaf_der]
            out["chain"] = [_describe(d) for d in chain_ders]
            out["leaf"] = out["chain"][0] if out["chain"] else None
    except (ssl.SSLError, OSError, ValueError) as exc:
        out["error"] = out["error"] or f"{type(exc).__name__}: {exc}"
    return out


def assess(facts: Dict[str, Any], now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """Turn raw cert facts into reasons + a health colour (green/yellow/red/gray)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    reasons: List[dict] = []
    public: Dict[str, Any] = {k: v for k, v in facts.items() if k not in ("chain", "leaf")}
    leaf = facts.get("leaf")

    def strip(c):  # drop private datetime objects before returning to clients
        return {k: v for k, v in c.items() if not k.startswith("_")}

    public["chain"] = [strip(c) for c in facts.get("chain", [])]
    if not facts.get("reachable") or not leaf:
        public.update(level="gray", reasons=[])
        if facts.get("error") and "private_address" not in str(facts["error"]):
            public["note"] = "Could not complete a TLS handshake on port 443."
        return {"cert": public, "reasons": reasons}

    host = facts["host"]
    days_left = (leaf["_na"] - now).days
    age_days = (now - leaf["_nb"]).days
    public.update(days_left=days_left, age_days=age_days)
    level = "green"

    kind = facts.get("verify_kind")
    if leaf["self_signed"] or kind == "self_signed":
        reasons.append(reason("self_signed_certificate", "The site presents a self-signed certificate that no browser trusts.", "high", {"issuer": leaf["issuer"]["cn"]}, "certificate"))
        level = "red"
    elif kind == "untrusted_issuer":
        reasons.append(reason("bad_certificate", "The certificate was issued by an authority your system does not trust.", "high", {"issuer": leaf["issuer"]["cn"]}, "certificate"))
        level = "red"
    if kind == "expired" or days_left < 0:
        reasons.append(reason("cert_expired", f"The certificate expired {abs(days_left)} days ago.", "high", {"not_after": leaf["not_after"]}, "certificate"))
        level = "red"
    elif days_left <= 14:
        reasons.append(reason("expiring_certificate", f"The certificate expires in {days_left} days.", "medium", {"days_left": days_left}, "certificate"))
        level = "red" if level == "red" else "yellow"
    elif days_left <= 30:
        reasons.append(reason("expiring_certificate", f"The certificate expires in {days_left} days.", "low", {"days_left": days_left}, "certificate"))
        level = "yellow" if level == "green" else level
    if kind == "hostname_mismatch" or not _host_matches(host, leaf["sans"], leaf["subject"]["cn"]):
        reasons.append(reason("cert_hostname_mismatch", f"The certificate is not valid for {host}.", "high", {"names": leaf["sans"][:5]}, "certificate"))
        level = "red"
    if not facts.get("verified") and not reasons:
        reasons.append(reason("bad_certificate", f"The certificate failed validation: {facts.get('verify_error') or 'unknown reason'}.", "high", {}, "certificate"))
        level = "red"
    if leaf["signature_hash"] in WEAK_SIG:
        reasons.append(reason("weak_tls", f"The certificate is signed with a weak hash ({leaf['signature_hash']}).", "medium", {}, "certificate"))
        level = "yellow" if level == "green" else level
    if leaf["key"].startswith("RSA") and leaf["key_bits"] < 2048:
        reasons.append(reason("weak_tls", f"The certificate uses a short key ({leaf['key']}).", "medium", {}, "certificate"))
        level = "yellow" if level == "green" else level
    if facts.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
        reasons.append(reason("weak_tls", f"The server negotiated an obsolete protocol ({facts['tls_version']}).", "medium", {}, "certificate"))
        level = "yellow" if level == "green" else level
    if facts.get("verified") and age_days <= 7:
        # valid but brand new: weak signal alone (free CAs issue instantly), useful with other evidence
        reasons.append(reason("new_certificate", f"The certificate was issued only {max(age_days, 0)} days ago.", "low", {"age_days": age_days}, "certificate"))
    public["level"] = level
    return {"cert": public, "reasons": findings.enrich(reasons, "certificate")}


def check(host: str, port: int = 443, **kw: Any) -> Dict[str, Any]:
    return assess(inspect(host, port, **kw))
