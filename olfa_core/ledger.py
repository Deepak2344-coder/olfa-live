"""Step 6: verifiable report ledger (integrity layer, no blockchain).

PUBLIC chain  `ledger`: id, record_id, revision, kind, commitment, status, ts, prev_hash, entry_hash.
              No URL, domain, note or reporter appears in it.
PRIVATE side  `ledger_records` (record -> domain, reporter hash) and `ledger_private` (canonical JSON + salt),
              kept so the server can recompute a commitment. The canonical JSON holds only the registrable
              domain, never a raw URL, email content or password.

commitment = SHA-256(canonical_json + salt)           entry_hash = SHA-256(prev_hash | entry fields)
The ledger proves a report's integrity and history, not that it is true.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64
NOTICE = "The ledger proves a report's integrity and history, not that it is true."
THREAT = ("phishing", "malware", "scam")
STATUSES = ("submitted", "validated", "disputed", "revised")


def canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def commitment_of(canonical: str, salt: str) -> str:
    return hashlib.sha256((canonical + salt).encode()).hexdigest()


def entry_hash_of(prev: str, record_id: int, revision: int, kind: str, commitment: str, status: str, ts: int) -> str:
    return hashlib.sha256("|".join([prev, str(record_id), str(revision), kind, commitment, status, str(ts)]).encode()).hexdigest()


class Ledger:
    def __init__(self, intel):
        self.intel = intel
        with intel._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, revision INTEGER NOT NULL,
                    kind TEXT NOT NULL, commitment TEXT NOT NULL, status TEXT NOT NULL, ts INTEGER NOT NULL,
                    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ledger_record ON ledger(record_id);
                CREATE TABLE IF NOT EXISTS ledger_records(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, reporter TEXT NOT NULL, UNIQUE(domain, reporter));
                CREATE TABLE IF NOT EXISTS ledger_private(
                    record_id INTEGER NOT NULL, revision INTEGER NOT NULL, canonical TEXT NOT NULL, salt TEXT NOT NULL,
                    PRIMARY KEY(record_id, revision));
                """
            )
        self._backfill()

    # ---- writing -----------------------------------------------------------
    def _append(self, c, record_id: int, revision: int, kind: str, commitment: str, status: str, ts: int) -> int:
        row = c.execute("SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        h = entry_hash_of(prev, record_id, revision, kind, commitment, status, ts)
        cur = c.execute("INSERT INTO ledger(record_id, revision, kind, commitment, status, ts, prev_hash, entry_hash) "
                        "VALUES(?,?,?,?,?,?,?,?)", (record_id, revision, kind, commitment, status, ts, prev, h))
        return cur.lastrowid

    def record(self, domain: str, reporter: str, verdict: str, note: str, brand: str = "", ts: Optional[float] = None) -> int:
        """Commit a report (revision 1) or a changed re-report (revision n+1). Returns the record id."""
        ts_i = int(ts if ts is not None else time.time())
        evidence: List[Dict[str, str]] = []
        if note:
            evidence.append({"type": "note_sha256", "value": hashlib.sha256(note.encode()).hexdigest()})
        if brand:
            evidence.append({"type": "impersonated_brand", "value": brand})
        with self.intel._conn() as c:
            c.execute("INSERT OR IGNORE INTO ledger_records(domain, reporter) VALUES(?,?)", (domain, reporter))
            rid = c.execute("SELECT id FROM ledger_records WHERE domain=? AND reporter=?", (domain, reporter)).fetchone()[0]
            last = c.execute("SELECT revision, canonical FROM ledger_private WHERE record_id=? ORDER BY revision DESC LIMIT 1", (rid,)).fetchone()
            revision = (last["revision"] + 1) if last else 1
            body = {"indicator_type": "domain", "domain": domain, "verdict": verdict, "summary": (note or "")[:280],
                    "evidence": evidence, "timestamp": ts_i, "revision": revision}
            if last:
                old = json.loads(last["canonical"])
                same = all(old.get(k) == body[k] for k in ("indicator_type", "domain", "verdict", "summary", "evidence"))
                if same:
                    return rid
            canon = canonical_json(body)
            salt = secrets.token_hex(16)
            c.execute("INSERT INTO ledger_private(record_id, revision, canonical, salt) VALUES(?,?,?,?)", (rid, revision, canon, salt))
            self._append(c, rid, revision, "commit" if revision == 1 else "revision", commitment_of(canon, salt),
                         "submitted" if revision == 1 else "revised", ts_i)
        return rid

    def sync_status(self, domain: str) -> None:
        """Move each record of a domain to validated/disputed from the existing reporter consensus."""
        consensus = self.intel.lookup(domain)["status"]
        now = int(time.time())
        with self.intel._conn() as c:
            for rec in c.execute("SELECT id FROM ledger_records WHERE domain=?", (domain,)).fetchall():
                rid = rec["id"]
                cur = c.execute("SELECT revision, status, commitment FROM ledger WHERE record_id=? ORDER BY id DESC LIMIT 1", (rid,)).fetchone()
                priv = c.execute("SELECT canonical FROM ledger_private WHERE record_id=? ORDER BY revision DESC LIMIT 1", (rid,)).fetchone()
                if not cur or not priv:
                    continue
                is_threat = json.loads(priv["canonical"])["verdict"] in THREAT
                desired = cur["status"]
                if consensus == "confirmed_malicious":
                    desired = "validated" if is_threat else "disputed"
                elif consensus == "confirmed_safe":
                    desired = "disputed" if is_threat else "validated"
                elif consensus == "disputed":
                    desired = "disputed"
                elif cur["status"] in ("validated", "disputed"):
                    desired = "revised" if cur["revision"] > 1 else "submitted"
                if desired != cur["status"]:
                    self._append(c, rid, cur["revision"], "status", cur["commitment"], desired, now)

    def _backfill(self) -> None:
        """Reports made before the ledger existed get a revision-1 record (their own timestamp)."""
        with self.intel._conn() as c:
            rows = c.execute("SELECT r.domain, r.reporter, r.verdict, r.note, r.created FROM reports r "
                             "LEFT JOIN ledger_records l ON l.domain=r.domain AND l.reporter=r.reporter WHERE l.id IS NULL").fetchall()
        for r in rows:
            self.record(r["domain"], r["reporter"], r["verdict"], r["note"] or "", "", r["created"])
        for d in {r["domain"] for r in rows}:
            self.sync_status(d)

    # ---- reading -----------------------------------------------------------
    def history(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self.intel._conn() as c:
            if not c.execute("SELECT 1 FROM ledger_records WHERE id=?", (record_id,)).fetchone():
                return None
            rows = c.execute("SELECT id, revision, kind, commitment, status, ts, prev_hash, entry_hash FROM ledger "
                             "WHERE record_id=? ORDER BY id", (record_id,)).fetchall()
        entries = [dict(r) for r in rows]
        return {"record_id": record_id, "entries": entries, "status": entries[-1]["status"] if entries else None,
                "revision": entries[-1]["revision"] if entries else None, "notice": NOTICE}

    def verify(self, record_id: int) -> Optional[Dict[str, Any]]:
        """Recompute the whole chain and every commitment of this record. Never raises on tampered data."""
        with self.intel._conn() as c:
            if not c.execute("SELECT 1 FROM ledger_records WHERE id=?", (record_id,)).fetchone():
                return None
            chain = c.execute("SELECT * FROM ledger ORDER BY id").fetchall()
            priv = {(r["revision"]): r for r in c.execute(
                "SELECT revision, canonical, salt FROM ledger_private WHERE record_id=?", (record_id,)).fetchall()}
        problems: List[str] = []
        prev = GENESIS
        for e in chain:
            if e["prev_hash"] != prev:
                problems.append(f"entry {e['id']}: link to the previous entry is broken")
            if entry_hash_of(e["prev_hash"], e["record_id"], e["revision"], e["kind"], e["commitment"], e["status"], e["ts"]) != e["entry_hash"]:
                problems.append(f"entry {e['id']}: contents do not match its hash")
            prev = e["entry_hash"]
        chain_ok = not problems
        commit_ok = True
        mine = [e for e in chain if e["record_id"] == record_id]
        for e in mine:
            if e["kind"] in ("commit", "revision"):
                p = priv.get(e["revision"])
                if not p or commitment_of(p["canonical"], p["salt"]) != e["commitment"]:
                    commit_ok = False
                    problems.append(f"entry {e['id']}: commitment does not match the stored report")
        return {"record_id": record_id, "valid": chain_ok and commit_ok and bool(mine), "chain_ok": chain_ok,
                "commitments_ok": commit_ok, "entries_checked": len(chain), "head": prev if chain else GENESIS,
                "revision": mine[-1]["revision"] if mine else None, "status": mine[-1]["status"] if mine else None,
                "last_entry_id": mine[-1]["id"] if mine else None,
                "problems": problems[:5], "notice": NOTICE}

    def chain_hash_at(self, entry_id: int):
        """Walk the chain from the start to entry_id, checking every link. Returns (ok, entry_hash_at_id)."""
        with self.intel._conn() as c:
            rows = c.execute("SELECT * FROM ledger WHERE id<=? ORDER BY id", (entry_id,)).fetchall()
        prev = GENESIS
        for e in rows:
            if e["prev_hash"] != prev or entry_hash_of(e["prev_hash"], e["record_id"], e["revision"], e["kind"],
                                                       e["commitment"], e["status"], e["ts"]) != e["entry_hash"]:
                return False, prev
            prev = e["entry_hash"]
        return bool(rows) and rows[-1]["id"] == entry_id, prev

    def head(self) -> str:
        with self.intel._conn() as c:
            row = c.execute("SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS
