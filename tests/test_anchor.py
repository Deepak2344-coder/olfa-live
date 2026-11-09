"""Step 6b: testnet anchoring with a FAKE node and signer. No real network, no real key."""
import os
import sqlite3
import tempfile

from olfa_core.anchor import Anchor, MAGIC
from olfa_core.intel import Intel

KEY = "0x" + "ab" * 32  # fake key used only to check it never leaks


class FakeNode:
    def __init__(self, fail=False):
        self.sent, self.fail, self.mined = [], fail, False

    def __call__(self, url, payload, **kw):
        m, p = payload["method"], payload["params"]
        if self.fail:
            return {"status": None, "body": "", "error": "ConnectionError", "json": None}
        res = {"eth_getTransactionCount": "0x5", "eth_gasPrice": "0x3b9aca00"}.get(m)
        if m == "eth_sendRawTransaction":
            self.sent.append(p[0]); res = "0x" + "11" * 32
        if m == "eth_getTransactionReceipt":
            res = {"blockNumber": "0x10"} if self.mined else None
        if m == "eth_getTransactionByHash":
            res = {"input": self.sent[-1].replace("RAW:", "")} if self.sent else None
        return {"status": 200, "body": "x", "error": None, "json": {"jsonrpc": "2.0", "id": 1, "result": res}}


def _sign(key, tx):
    assert tx["to"] == "0xME" and tx["value"] == 0 and tx["data"].startswith("0x" + MAGIC.hex())
    return tx["data"], "0xME"  # the fake "raw tx" is just the data, so the fake node can echo it back


def _setup(fail=False, min_seconds=600, db=":memory:"):
    i = Intel(db)
    node = FakeNode(fail)
    i.anchor = Anchor(i, rpc="https://node.example", key=KEY, min_seconds=min_seconds, signer=_sign,
                      address_of=lambda k: "0xME", post=node)
    return i, node


def _rep(i, tok="reporter-token-1", url="http://bad-site.com/"):
    return i.report(url, "phishing", tok, "x")["ledger_id"]


def test_not_configured_is_reported_not_crashed():
    i = Intel(":memory:")
    assert not i.anchor.configured
    assert i.anchor.anchor()["status"] == "not_configured"
    assert i.anchor.status()["configured"] is False and i.anchor.coverage(1) == {"covered": False, "message": "Not anchored yet."}
    assert i.anchor.verify_onchain()["checked"] is False


def test_anchor_puts_only_the_chain_head_in_the_transaction():
    i, node = _setup()
    lid = _rep(i)
    out = i.anchor.anchor()
    assert out["status"] == "submitted" and out["head"] == i.ledger.head()
    assert node.sent == ["0x" + MAGIC.hex() + i.ledger.head()]
    assert "bad-site" not in node.sent[0] and KEY not in str(out)
    assert i.anchor.anchor()["status"] == "already_anchored"
    assert lid


def test_rate_gap_between_anchors():
    i, node = _setup(min_seconds=600)
    _rep(i); i.anchor.anchor()
    _rep(i, tok="reporter-token-2", url="http://other-bad.com/")
    assert i.anchor.anchor()["status"] == "waiting"
    assert i.anchor.anchor(min_gap=0)["status"] == "submitted" and len(node.sent) == 2


def test_node_failure_says_not_anchored_and_reports_still_work():
    i, node = _setup(fail=True)
    lid = _rep(i)
    out = i.anchor.anchor()
    assert out["status"] == "failed" and "Not anchored" in out["message"] and KEY not in str(out)
    assert i.ledger.verify(lid)["valid"] and i.anchor.coverage(i.ledger.verify(lid)["last_entry_id"])["covered"] is False


def test_coverage_matches_then_detects_rewritten_history():
    path = os.path.join(tempfile.mkdtemp(), "a.db")
    i, _ = _setup(db=path)
    lid = _rep(i)
    i.anchor.anchor()
    last = i.ledger.verify(lid)["last_entry_id"]
    c = i.anchor.coverage(last)
    assert c["covered"] and c["matches_ledger"] and c["tx_hash"].startswith("0x")
    con = sqlite3.connect(path)
    con.execute("UPDATE ledger SET status='validated' WHERE id=?", (last,))
    con.commit(); con.close()
    assert i.anchor.coverage(last)["matches_ledger"] is False


def test_new_entries_after_an_anchor_are_not_covered_yet():
    i, _ = _setup()
    _rep(i); i.anchor.anchor()
    lid2 = _rep(i, tok="reporter-token-2", url="http://other-bad.com/")
    assert i.anchor.coverage(i.ledger.verify(lid2)["last_entry_id"])["covered"] is False


def test_verify_onchain_and_status_confirmation():
    i, node = _setup()
    _rep(i); i.anchor.anchor()
    assert i.anchor.status()["anchors"][0]["status"] == "submitted"
    node.mined = True
    st = i.anchor.status()["anchors"][0]
    assert st["status"] == "confirmed" and st["block"] == 16
    v = i.anchor.verify_onchain()
    assert v["checked"] and v["valid"] and v["on_chain_matches_anchor"] and v["ledger_matches_anchor"]
    node.sent[-1] = "0x" + MAGIC.hex() + "00" * 32  # the chain says something else
    assert i.anchor.verify_onchain()["valid"] is False
