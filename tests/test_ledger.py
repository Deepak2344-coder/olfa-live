"""Step 6: hash-chained report ledger. Tampering must break verification; no raw URL on the ledger."""
import json
import os
import sqlite3
import tempfile

from olfa_core.intel import Intel
from olfa_core.ledger import GENESIS, NOTICE


def _db():
    return os.path.join(tempfile.mkdtemp(), "t.db")


def _rep(i, url="http://paypa1.xyz/login?user=bob@example.com&pw=secret1", verdict="phishing", tok="reporter-token-1", note="fake login page"):
    return i.report(url, verdict, tok, note)


def test_report_creates_verifiable_record():
    i = Intel(":memory:")
    lid = _rep(i)["ledger_id"]
    v = i.ledger.verify(lid)
    assert v["valid"] and v["chain_ok"] and v["commitments_ok"] and v["revision"] == 1 and v["status"] == "submitted"
    assert NOTICE in v["notice"] and v["notice"] == NOTICE
    h = i.ledger.history(lid)
    assert h["entries"][0]["prev_hash"] == GENESIS and h["entries"][0]["kind"] == "commit"


def test_no_raw_url_or_personal_data_on_the_ledger():
    path = _db()
    i = Intel(path)
    _rep(i)
    con = sqlite3.connect(path)
    dump = json.dumps([list(r) for r in con.execute("SELECT * FROM ledger")])
    for bad in ("http", "paypa1", "bob@example.com", "secret1", "fake login", "login"):
        assert bad not in dump
    canon = con.execute("SELECT canonical FROM ledger_private").fetchone()[0]
    assert "http" not in canon and "secret1" not in canon and "bob@" not in canon  # private canonical holds the domain only
    assert json.loads(canon)["domain"] == "paypa1.xyz"
    con.close()


def test_tampering_with_a_commitment_breaks_verification():
    path = _db()
    i = Intel(path)
    lid = _rep(i)["ledger_id"]
    con = sqlite3.connect(path)
    con.execute("UPDATE ledger SET commitment=? WHERE record_id=?", ("0" * 64, lid))
    con.commit(); con.close()
    v = i.ledger.verify(lid)
    assert not v["valid"] and not v["chain_ok"]


def test_tampering_with_status_or_timestamp_breaks_the_chain():
    path = _db()
    i = Intel(path)
    lid = _rep(i)["ledger_id"]
    con = sqlite3.connect(path)
    con.execute("UPDATE ledger SET status='validated' WHERE record_id=?", (lid,))
    con.commit(); con.close()
    assert not i.ledger.verify(lid)["valid"]


def test_tampering_with_the_stored_report_breaks_the_commitment():
    path = _db()
    i = Intel(path)
    lid = _rep(i)["ledger_id"]
    con = sqlite3.connect(path)
    con.execute("UPDATE ledger_private SET canonical=REPLACE(canonical,'phishing','safe')")
    con.commit(); con.close()
    v = i.ledger.verify(lid)
    assert v["chain_ok"] and not v["commitments_ok"] and not v["valid"]


def test_deleting_or_reordering_an_earlier_entry_is_detected():
    path = _db()
    i = Intel(path)
    first = _rep(i, tok="reporter-token-1")["ledger_id"]
    second = _rep(i, url="http://other-bad.com/", tok="reporter-token-2")["ledger_id"]
    con = sqlite3.connect(path)
    con.execute("DELETE FROM ledger WHERE record_id=?", (first,))
    con.commit(); con.close()
    assert not i.ledger.verify(second)["valid"]  # the chain no longer links up


def test_revision_creates_a_new_linked_entry_and_unchanged_rereport_does_not():
    i = Intel(":memory:")
    lid = _rep(i)["ledger_id"]
    assert _rep(i)["ledger_id"] == lid and len(i.ledger.history(lid)["entries"]) == 1  # same content: no new revision
    assert _rep(i, verdict="scam")["ledger_id"] == lid
    h = i.ledger.history(lid)
    assert [e["revision"] for e in h["entries"]] == [1, 2]
    assert h["entries"][1]["kind"] == "revision" and h["entries"][1]["status"] == "revised"
    assert h["entries"][1]["prev_hash"] == h["entries"][0]["entry_hash"]
    assert i.ledger.verify(lid)["valid"]


def test_status_follows_reporter_consensus():
    i = Intel(":memory:")
    a = _rep(i, url="http://paypa1.xyz/", tok="reporter-token-A")["ledger_id"]
    for n in range(2, 5):
        _rep(i, url="http://paypa1.xyz/", tok=f"reporter-token-{n}")
    assert i.lookup("paypa1.xyz")["status"] == "confirmed_malicious"
    assert i.ledger.history(a)["status"] == "validated"
    dissent = i.report("http://paypa1.xyz/", "safe", "reporter-token-Z", "looks fine")["ledger_id"]
    assert i.ledger.history(dissent)["status"] == "disputed"  # disagrees with the confirmed consensus
    assert i.ledger.verify(a)["valid"] and i.ledger.verify(dissent)["valid"]


def test_old_reports_are_backfilled_and_recent_exposes_ledger_id():
    path = _db()
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE reporters(id TEXT PRIMARY KEY, reputation REAL NOT NULL DEFAULT 1.0, created REAL NOT NULL);"
        "CREATE TABLE reports(domain TEXT NOT NULL, reporter TEXT NOT NULL, verdict TEXT NOT NULL, url TEXT, note TEXT,"
        " created REAL NOT NULL, PRIMARY KEY(domain, reporter));"
        "CREATE TABLE actions(reporter TEXT NOT NULL, at REAL NOT NULL);"
        "INSERT INTO reporters VALUES('r1', 1.0, 1.0);"
        "INSERT INTO reports VALUES('bad-site.com','r1','phishing','http://bad-site.com/x','old',1.0);")
    con.commit(); con.close()
    i = Intel(path)
    rec = i.recent()[0]
    assert rec["ledger_id"] and i.ledger.verify(rec["ledger_id"])["valid"]
    assert Intel(path).ledger.head() == i.ledger.head()  # reopening adds nothing


def test_unknown_record_returns_none():
    i = Intel(":memory:")
    assert i.ledger.verify(999) is None and i.ledger.history(999) is None
