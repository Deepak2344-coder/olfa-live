"""Step 6b: anchor the ledger's latest chain hash on a public EVM testnet (e.g. Sepolia).

How: a 0-value transaction from the Olfa wallet to itself whose data is b"OLFA1" + the 32-byte chain head.
Anyone can read that transaction on a block explorer and compare it with the ledger: if history before that
point was rewritten, the head would no longer match. Only the hash goes on-chain, never any report content.

Config (environment only; the key is never printed, logged or stored):
  OLFA_ANCHOR_RPC           https JSON-RPC URL of a testnet node
  OLFA_ANCHOR_KEY           private key of a TESTNET-ONLY wallet (needs free faucet coins)
  OLFA_ANCHOR_CHAIN_ID      default 11155111 (Sepolia)
  OLFA_ANCHOR_MIN_SECONDS   minimum gap between automatic anchors, default 600
  OLFA_ANCHOR_EXPLORER      tx URL prefix, default https://sepolia.etherscan.io/tx/
Every failure is reported as "not anchored"; reports and verification keep working without the chain.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import guarded_http

MAGIC = b"OLFA1"
GAS_LIMIT = 40000  # 21000 base + data bytes, with margin
NOTICE = "The anchor proves the ledger had this exact history at that time, not that any report is true."


def _eth_sign(key: str, tx: Dict[str, Any]) -> Tuple[str, str]:
    """Sign with eth-account (optional dependency). Returns (raw_tx_hex, address)."""
    from eth_account import Account  # lazy: only needed when anchoring is configured
    acct = Account.from_key(key)
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex().removeprefix("0x"), acct.address


def _eth_address(key: str) -> str:
    from eth_account import Account
    return Account.from_key(key).address


class Anchor:
    def __init__(self, intel, *, rpc: Optional[str] = None, key: Optional[str] = None, chain_id: Optional[int] = None,
                 min_seconds: Optional[int] = None, signer: Optional[Callable] = None,
                 address_of: Optional[Callable] = None, post: Optional[Callable] = None):
        self.intel = intel
        self.rpc = rpc if rpc is not None else os.environ.get("OLFA_ANCHOR_RPC", "")
        self._key = key if key is not None else os.environ.get("OLFA_ANCHOR_KEY", "")
        self.chain_id = int(chain_id or os.environ.get("OLFA_ANCHOR_CHAIN_ID") or 11155111)
        self.min_seconds = int(min_seconds if min_seconds is not None else os.environ.get("OLFA_ANCHOR_MIN_SECONDS", "600"))
        self.explorer = os.environ.get("OLFA_ANCHOR_EXPLORER", "https://sepolia.etherscan.io/tx/")
        self._sign = signer or _eth_sign
        self._address_of = address_of or _eth_address
        self._post = post or guarded_http.post_json
        self._lock = threading.Lock()
        with intel._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_anchors(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, entry_id INTEGER NOT NULL, head TEXT NOT NULL,
                    tx_hash TEXT NOT NULL, chain_id INTEGER NOT NULL, ts INTEGER NOT NULL,
                    status TEXT NOT NULL, block INTEGER);
                """
            )

    @property
    def configured(self) -> bool:
        return bool(self.rpc and self._key)

    # ---- chain access (guarded, never raises) ---------------------------------
    def _call(self, method: str, params: list) -> Tuple[Any, Optional[str]]:
        r = self._post(self.rpc, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10)
        j = r.get("json")
        if r.get("error") or not isinstance(j, dict):
            return None, r.get("error") or "no answer from the node"
        if j.get("error"):
            return None, str((j["error"] or {}).get("message", "node error"))[:120]
        return j.get("result"), None

    # ---- writing ---------------------------------------------------------------
    def anchor(self, min_gap: Optional[int] = None) -> Dict[str, Any]:
        if not self.configured:
            return {"status": "not_configured", "message": "Anchoring is not set up on this server."}
        if not self._lock.acquire(blocking=False):
            return {"status": "busy", "message": "An anchor is already being sent."}
        try:
            with self.intel._conn() as c:
                last = c.execute("SELECT id, entry_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
                prev = c.execute("SELECT head, ts FROM ledger_anchors ORDER BY id DESC LIMIT 1").fetchone()
            if not last:
                return {"status": "nothing_to_anchor", "message": "The ledger is empty."}
            if prev and prev["head"] == last["entry_hash"]:
                return {"status": "already_anchored", "message": "The latest ledger state is already anchored."}
            gap = self.min_seconds if min_gap is None else min_gap
            if prev and time.time() - prev["ts"] < gap:
                return {"status": "waiting", "message": "An anchor was sent recently; the next one is due later."}
            try:
                addr = self._address_of(self._key)
                nonce, e1 = self._call("eth_getTransactionCount", [addr, "pending"])
                price, e2 = self._call("eth_gasPrice", [])
                if e1 or e2 or nonce is None or price is None:
                    return {"status": "failed", "message": "Not anchored: the test network did not answer."}
                tx = {"chainId": self.chain_id, "nonce": int(nonce, 16), "to": addr, "value": 0, "gas": GAS_LIMIT,
                      "gasPrice": int(int(price, 16) * 1.25) + 1, "data": "0x" + MAGIC.hex() + last["entry_hash"]}
                raw, _ = self._sign(self._key, tx)
                txh, err = self._call("eth_sendRawTransaction", [raw])
            except Exception as exc:  # noqa: BLE001 - never include exception text: it could touch key material
                return {"status": "failed", "message": f"Not anchored ({type(exc).__name__})."}
            if err or not txh:
                return {"status": "failed", "message": "Not anchored: " + (err or "the node refused the transaction") +
                        ". The wallet may have no test coins."}
            now = int(time.time())
            with self.intel._conn() as c:
                c.execute("INSERT INTO ledger_anchors(entry_id, head, tx_hash, chain_id, ts, status) VALUES(?,?,?,?,?,?)",
                          (last["id"], last["entry_hash"], txh, self.chain_id, now, "submitted"))
            return {"status": "submitted", "tx_hash": txh, "entry_id": last["id"], "head": last["entry_hash"],
                    "url": self.explorer + txh}
        finally:
            self._lock.release()

    # ---- reading ---------------------------------------------------------------
    def _rows(self, limit: int = 5) -> List[Dict[str, Any]]:
        with self.intel._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM ledger_anchors ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def status(self) -> Dict[str, Any]:
        """Latest anchors; unconfirmed ones are re-checked against the node (not checked if it is down)."""
        rows = self._rows()
        if self.configured:
            for r in [x for x in rows if x["status"] == "submitted"][:3]:
                rec, err = self._call("eth_getTransactionReceipt", [r["tx_hash"]])
                if not err and isinstance(rec, dict) and rec.get("blockNumber"):
                    r["status"], r["block"] = "confirmed", int(rec["blockNumber"], 16)
                    with self.intel._conn() as c:
                        c.execute("UPDATE ledger_anchors SET status='confirmed', block=? WHERE id=?", (r["block"], r["id"]))
        for r in rows:
            r["url"] = self.explorer + r["tx_hash"]
        return {"configured": self.configured, "chain_id": self.chain_id, "anchors": rows, "notice": NOTICE,
                "message": None if self.configured else "Anchoring is not set up on this server."}

    def coverage(self, entry_id: Optional[int]) -> Dict[str, Any]:
        """Local only: is this ledger entry inside an anchored prefix, and does the anchored head still match?"""
        if entry_id is None:
            return {"covered": False}
        with self.intel._conn() as c:
            a = c.execute("SELECT * FROM ledger_anchors WHERE entry_id>=? ORDER BY entry_id LIMIT 1", (entry_id,)).fetchone()
        if not a:
            return {"covered": False, "message": "Not anchored yet."}
        ok, h = self.intel.ledger.chain_hash_at(a["entry_id"])
        return {"covered": True, "tx_hash": a["tx_hash"], "url": self.explorer + a["tx_hash"], "anchored_entry": a["entry_id"],
                "status": a["status"], "matches_ledger": bool(ok and h == a["head"])}

    def verify_onchain(self) -> Dict[str, Any]:
        """Independent check: read the latest anchor transaction from the node and compare it with the ledger."""
        rows = self._rows(1)
        if not rows:
            return {"checked": False, "message": "Nothing is anchored yet."}
        if not self.configured:
            return {"checked": False, "message": "Not checked: no test-network connection is configured."}
        a = rows[0]
        tx, err = self._call("eth_getTransactionByHash", [a["tx_hash"]])
        if err or not isinstance(tx, dict):
            return {"checked": False, "message": "Not checked: the test network did not return the transaction."}
        ok, h = self.intel.ledger.chain_hash_at(a["entry_id"])
        want = ("0x" + MAGIC.hex() + a["head"]).lower()
        on_chain = str(tx.get("input", "")).lower() == want
        return {"checked": True, "tx_hash": a["tx_hash"], "url": self.explorer + a["tx_hash"], "on_chain_matches_anchor": on_chain,
                "ledger_matches_anchor": bool(ok and h == a["head"]), "valid": bool(on_chain and ok and h == a["head"]), "notice": NOTICE}
