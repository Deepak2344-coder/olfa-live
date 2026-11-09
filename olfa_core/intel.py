"""Pillar 4: collaborative threat intelligence.

A small SQLite store of community verdicts with:
  * one vote per reporter per domain (re-voting replaces the old vote),
  * reporter reputation (agree with consensus -> weight up, disagree -> down),
  * time decay on threat reports (stale reports fade),
  * a consensus rule that needs several independent reporters before a domain is
    "confirmed", so one account cannot blocklist (or whitelist) a site alone.

Limits (documented in README): reporter ids are anonymous API tokens, so a
determined attacker can create many of them. Real deployments need accounts,
rate limits per IP and moderator review for high-impact domains.
"""

from __future__ import annotations

import hashlib
import math
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from .schema import reason
from .urlparts import host_of, registrable

THREAT_VERDICTS = ("phishing", "malware", "scam")
SAFE_VERDICT = "safe"
HALF_LIFE_DAYS = 45.0
CONFIRM_WEIGHT = 2.5       # weighted votes needed to call a domain confirmed
CONFIRM_REPORTERS = 2      # ...from at least this many distinct reporters
MAX_NOTE = 280
RATE_LIMIT_PER_HOUR = 30


class Intel:
    def __init__(self, path: str = "olfa_intel.db"):
        self.path = path
        self._lock = threading.Lock()
        self._mem = sqlite3.connect(path, check_same_thread=False) if path == ":memory:" else None
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS reporters(id TEXT PRIMARY KEY, reputation REAL NOT NULL DEFAULT 1.0, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS reports(
                    domain TEXT NOT NULL, reporter TEXT NOT NULL, verdict TEXT NOT NULL, url TEXT, note TEXT,
                    created REAL NOT NULL, PRIMARY KEY(domain, reporter));
                CREATE INDEX IF NOT EXISTS reports_domain ON reports(domain);
                CREATE TABLE IF NOT EXISTS actions(reporter TEXT NOT NULL, at REAL NOT NULL);
                """
            )
        self._migrate()
        from .ledger import Ledger  # lazy: ledger uses this class's connection helper
        self.ledger = Ledger(self)
        from .anchor import Anchor
        self.anchor = Anchor(self)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._mem or sqlite3.connect(self.path)
            try:
                conn.row_factory = sqlite3.Row
                yield conn
                conn.commit()
            finally:
                if not self._mem:
                    conn.close()

    # ---- infrastructure observations (step 5) ------------------------
    SCHEMA_VERSION = 2

    def _migrate(self) -> None:
        """Additive only: old reports are never altered. v2 adds `observations` and backfills brands."""
        with self._conn() as c:
            ver = c.execute("PRAGMA user_version").fetchone()[0]
            if ver >= self.SCHEMA_VERSION:
                return
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations(
                    domain TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
                    seen REAL NOT NULL, PRIMARY KEY(domain, kind, value));
                CREATE INDEX IF NOT EXISTS observations_kv ON observations(kind, value);
                """
            )
            domains = [r[0] for r in c.execute("SELECT DISTINCT domain FROM reports").fetchall()]
            c.execute(f"PRAGMA user_version = {int(self.SCHEMA_VERSION)}")
        from .correlate import brand_of_host  # lazy: correlate imports this module's helpers
        for d in domains:
            b = brand_of_host(d)
            if b:
                self.observe(d, {"brand": [b]}, "report")

    def observe(self, domain: str, facts: Dict[str, List[str]], source: str) -> None:
        """Record infrastructure facts (ip, asn, ns, cert, brand) seen for a registrable domain."""
        now = time.time()
        rows = [(domain, k, str(v).lower()[:200], source, now) for k, vals in facts.items() for v in (vals or []) if v]
        if not domain or not rows:
            return
        with self._conn() as c:
            c.executemany(
                "INSERT INTO observations(domain, kind, value, source, seen) VALUES(?,?,?,?,?) "
                "ON CONFLICT(domain, kind, value) DO UPDATE SET seen=excluded.seen", rows)

    def observations(self, domain: str) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        with self._conn() as c:
            for r in c.execute("SELECT kind, value FROM observations WHERE domain=?", (domain,)).fetchall():
                out.setdefault(r["kind"], []).append(r["value"])
        return out

    def domains_with(self, kind: str, value: str, exclude: str, limit: int = 25) -> List[str]:
        with self._conn() as c:
            rows = c.execute("SELECT DISTINCT domain FROM observations WHERE kind=? AND value=? AND domain<>? "
                             "ORDER BY seen DESC LIMIT ?", (kind, value.lower(), exclude, int(limit))).fetchall()
        return [r[0] for r in rows]

    def report_domains(self, domain: str) -> List[str]:
        """Distinct report URLs' hosts for a domain (same registrable domain, other subdomains)."""
        with self._conn() as c:
            rows = c.execute("SELECT DISTINCT url FROM reports WHERE domain=? LIMIT 50", (domain,)).fetchall()
        return [r[0] for r in rows if r[0]]

    # ---- identity -------------------------------------------------------
    @staticmethod
    def reporter_id(token: str) -> str:
        """Store only a hash of the client's anonymous token."""
        return hashlib.sha256(("olfa-reporter:" + token).encode()).hexdigest()[:24]

    # ---- writing --------------------------------------------------------
    def report(self, url_or_host: str, verdict: str, token: str, note: str = "") -> Dict[str, Any]:
        raw_v = (verdict or "").strip().lower()
        alias_map = {
            "secure": "safe",
            "safe": "safe",
            "phishing": "phishing",
            "phish": "phishing",
            "malicious": "malware",
            "malware": "malware",
            "scam": "scam",
            "suspicious": "scam",
            "fraud": "scam",
            "other": "scam",
        }
        verdict = alias_map.get(raw_v, raw_v)
        if verdict not in THREAT_VERDICTS + (SAFE_VERDICT,):
            raise ValueError("verdict must be one of: " + ", ".join(THREAT_VERDICTS + (SAFE_VERDICT,)))
        if not token or len(token) < 8:
            raise ValueError("a reporter token of at least 8 characters is required")
        host = host_of(url_or_host if "://" in url_or_host else "http://" + url_or_host)
        if not host:
            raise ValueError("could not read a host from the report")
        domain = registrable(host)
        rid = self.reporter_id(token)
        now = time.time()
        with self._conn() as c:
            c.execute("INSERT OR IGNORE INTO reporters(id, created) VALUES(?, ?)", (rid, now))
            recent = c.execute("SELECT COUNT(*) FROM actions WHERE reporter=? AND at>?", (rid, now - 3600)).fetchone()[0]
            if recent >= RATE_LIMIT_PER_HOUR:
                raise PermissionError("rate limit: too many reports this hour")
            c.execute("INSERT INTO actions(reporter, at) VALUES(?, ?)", (rid, now))
            c.execute(
                "INSERT INTO reports(domain, reporter, verdict, url, note, created) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(domain, reporter) DO UPDATE SET verdict=excluded.verdict, url=excluded.url, note=excluded.note, created=excluded.created",
                (domain, rid, verdict, url_or_host[:300], note[:MAX_NOTE], now),
            )
        b = ""
        try:
            from .correlate import brand_of_host
            b = brand_of_host(host)
            if b:
                self.observe(domain, {"brand": [b]}, "report")
        except Exception:  # noqa: BLE001 - correlation data is optional
            pass
        self._settle(domain)
        ledger_id = None
        try:  # integrity record: only a commitment goes on the ledger
            ledger_id = self.ledger.record(domain, rid, verdict, note[:MAX_NOTE], b, now)
            self.ledger.sync_status(domain)
        except Exception:  # noqa: BLE001 - a ledger problem must not lose the report
            pass
        out = self.lookup(domain)
        out["ledger_id"] = ledger_id
        return out

    def _settle(self, domain: str) -> None:
        """Once a domain is confirmed, nudge reputation of reporters who agreed/disagreed."""
        status = self.lookup(domain)
        if status["status"] not in ("confirmed_malicious", "confirmed_safe"):
            return
        want_threat = status["status"] == "confirmed_malicious"
        with self._conn() as c:
            for row in c.execute("SELECT reporter, verdict FROM reports WHERE domain=?", (domain,)).fetchall():
                agrees = (row["verdict"] in THREAT_VERDICTS) == want_threat
                c.execute("UPDATE reporters SET reputation = MIN(3.0, MAX(0.1, reputation + ?)) WHERE id=?",
                          (0.05 if agrees else -0.2, row["reporter"]))

    # ---- reading --------------------------------------------------------
    def lookup(self, url_or_host: str) -> Dict[str, Any]:
        host = host_of(url_or_host if "://" in url_or_host else "http://" + url_or_host) or url_or_host.lower()
        domain = registrable(host)
        now = time.time()
        threat_w = safe_w = 0.0
        threat_n = safe_n = 0
        kinds: Dict[str, float] = {}
        with self._conn() as c:
            rows = c.execute(
                "SELECT r.verdict, r.created, r.note, p.reputation FROM reports r JOIN reporters p ON p.id=r.reporter WHERE r.domain=?",
                (domain,),
            ).fetchall()
        notes: List[str] = []
        for r in rows:
            decay = 0.5 ** (((now - r["created"]) / 86400.0) / HALF_LIFE_DAYS)
            w = r["reputation"] * (decay if r["verdict"] in THREAT_VERDICTS else max(decay, 0.5))
            if r["verdict"] in THREAT_VERDICTS:
                threat_w += w
                threat_n += 1
                kinds[r["verdict"]] = kinds.get(r["verdict"], 0) + w
                if r["note"]:
                    notes.append(r["note"])
            else:
                safe_w += w
                safe_n += 1
        status = "unknown"
        if threat_n or safe_n:
            if threat_w >= CONFIRM_WEIGHT and threat_n >= CONFIRM_REPORTERS and threat_w > 1.5 * safe_w:
                status = "confirmed_malicious"
            elif safe_w >= CONFIRM_WEIGHT and safe_n >= CONFIRM_REPORTERS and safe_w > 1.5 * threat_w:
                status = "confirmed_safe"
            elif threat_w > safe_w:
                status = "reported"
            elif safe_w > threat_w:
                status = "reported_safe"
            else:
                status = "disputed"
        return {"domain": domain, "status": status, "threat_weight": round(threat_w, 3), "safe_weight": round(safe_w, 3),
                "threat_reports": threat_n, "safe_reports": safe_n,
                "top_verdict": max(kinds, key=kinds.get) if kinds else None, "notes": notes[:3]}

    def reasons_for(self, lookup: Dict[str, Any]) -> List[dict]:
        s = lookup["status"]
        d = {"domain": lookup["domain"], "reports": lookup["threat_reports"], "weight": lookup["threat_weight"]}
        if s == "confirmed_malicious":
            return [reason("community_confirmed", f"{lookup['threat_reports']} independent reporters confirmed this domain as {lookup['top_verdict'] or 'malicious'}.", "high", d, "intel")]
        if s == "reported":
            return [reason("community_reported", f"{lookup['threat_reports']} user(s) reported this domain, but it is not yet confirmed.", "medium", d, "intel")]
        if s == "disputed":
            return [reason("community_reported", "Users disagree about this domain.", "low", d, "intel")]
        return []

    def recent(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Newest reports for the community page. Reporter identity is not included."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT domain, verdict, note, url, created, (SELECT l.id FROM ledger_records l WHERE l.domain=reports.domain "
                "AND l.reporter=reports.reporter) AS ledger_id FROM reports ORDER BY created DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [{"domain": r["domain"], "verdict": r["verdict"], "note": r["note"] or "",
                 "url": r["url"] or "", "created": r["created"], "ledger_id": r["ledger_id"]} for r in rows]

    def feed(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Confirmed-malicious domains, for extensions' declarativeNetRequest rules."""
        with self._conn() as c:
            domains = [r[0] for r in c.execute("SELECT DISTINCT domain FROM reports").fetchall()]
        out = []
        for d in domains:
            s = self.lookup(d)
            if s["status"] == "confirmed_malicious":
                out.append({"domain": d, "verdict": s["top_verdict"], "reports": s["threat_reports"], "weight": s["threat_weight"]})
        return sorted(out, key=lambda x: -x["weight"])[:limit]

    def stats(self) -> Dict[str, Any]:
        with self._conn() as c:
            return {"reports": c.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
                    "domains": c.execute("SELECT COUNT(DISTINCT domain) FROM reports").fetchone()[0],
                    "reporters": c.execute("SELECT COUNT(*) FROM reporters").fetchone()[0]}
