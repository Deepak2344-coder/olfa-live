"""Step 5: one test per matching rule, the DB migration, and report/scan recording. No network."""
import os
import sqlite3
import tempfile

from olfa_core import correlate
from olfa_core.intel import Intel


def _flag(intel, domain, n=1):
    for i in range(n):
        intel.report(f"http://{domain}/", "phishing", f"token-{domain}-{i}-xxxxxxxx")


def _rules(result, other):
    for link in result["related"]:
        if link["domain"] == other:
            return {m["rule"] for m in link["matches"]}
    return None


def test_shared_certificate_is_strong_and_shown_without_reports():
    i = Intel(":memory:")
    i.observe("a-site.com", {"cert": ["ab12"]}, "scan")
    i.observe("b-site.com", {"cert": ["ab12"]}, "scan")
    r = correlate.related(i, "https://a-site.com/")
    link = r["related"][0]
    assert link["domain"] == "b-site.com" and link["strength"] == "strong"
    assert link["matches"][0]["evidence"] == {"sha256": "ab12"}


def test_shared_ip_needs_a_threat_report_on_either_side():
    i = Intel(":memory:")
    i.observe("one-site.com", {"ip": ["203.0.113.9"]}, "scan")
    i.observe("two-site.com", {"ip": ["203.0.113.9"]}, "scan")
    assert correlate.related(i, "one-site.com")["related"] == []  # plain shared hosting is not a link
    _flag(i, "two-site.com")
    r = correlate.related(i, "one-site.com")
    assert _rules(r, "two-site.com") == {"shared_ip"}
    assert r["related"][0]["matches"][0]["evidence"] == {"ip": "203.0.113.9"}
    assert r["related"][0]["strength"] == "medium"


def test_shared_nameserver_common_provider_is_weak_and_hidden_unless_other_flagged():
    i = Intel(":memory:")
    i.observe("one-site.com", {"ns": ["ns1.cloudflare.com"]}, "scan")
    i.observe("two-site.com", {"ns": ["ns1.cloudflare.com"]}, "scan")
    assert correlate.related(i, "one-site.com")["related"] == []
    _flag(i, "two-site.com")
    link = correlate.related(i, "one-site.com")["related"][0]
    assert link["strength"] == "weak" and link["matches"][0]["rule"] == "shared_nameserver"


def test_shared_nameserver_uncommon_is_medium():
    i = Intel(":memory:")
    i.observe("one-site.com", {"ns": ["ns.rare-dns.example"]}, "scan")
    i.observe("two-site.com", {"ns": ["ns.rare-dns.example"]}, "scan")
    _flag(i, "one-site.com")  # own side flagged is enough for an infrastructure-only link
    link = correlate.related(i, "one-site.com")["related"][0]
    assert link["strength"] == "medium" and link["matches"][0]["evidence"] == {"nameserver": "ns.rare-dns.example"}


def test_shared_network_asn_is_weak_and_needs_the_other_domain_flagged():
    i = Intel(":memory:")
    i.observe("one-site.com", {"asn": ["AS64500"]}, "scan")
    i.observe("two-site.com", {"asn": ["AS64500"]}, "scan")
    _flag(i, "one-site.com")
    assert correlate.related(i, "one-site.com")["related"] == []  # only my side is flagged
    _flag(i, "two-site.com")
    assert _rules(correlate.related(i, "one-site.com"), "two-site.com") == {"shared_network"}


def test_same_impersonated_brand_links_lookalikes():
    i = Intel(":memory:")
    _flag(i, "paypal-login-secure.com")  # report records brand 'paypal'
    _flag(i, "secure-paypal-verify.top")
    r = correlate.related(i, "https://paypal-login-secure.com/signin")
    assert r["impersonated_brand"] == "paypal"
    assert _rules(r, "secure-paypal-verify.top") == {"same_impersonated_brand"}


def test_unrelated_brand_or_clean_domain_has_no_links():
    i = Intel(":memory:")
    _flag(i, "paypal-login-secure.com")
    r = correlate.related(i, "https://example.org/")
    assert r["related"] == [] and "No related incidents" in r["summary"]


def test_matches_are_merged_per_domain_with_all_evidence():
    i = Intel(":memory:")
    i.observe("one-site.com", {"ip": ["203.0.113.9"], "cert": ["ff"]}, "scan")
    i.observe("two-site.com", {"ip": ["203.0.113.9"], "cert": ["ff"]}, "scan")
    link = correlate.related(i, "one-site.com")["related"][0]
    assert {m["rule"] for m in link["matches"]} == {"shared_certificate", "shared_ip"}
    assert link["strength"] == "strong"


def test_facts_from_scan_uses_only_observed_values():
    scan = {"dns": {"a": ["203.0.113.5"], "aaaa": [], "ns": ["ns1.example.net."], "asn": {"asn": "AS64500"}},
            "certificate": {"chain": [{"sha256": "cd34"}]},
            "reasons": [{"code": "brand_impersonation", "details": {"brand": "PayPal"}}]}
    f = correlate.facts_from_scan(scan)
    assert f == {"ip": ["203.0.113.5"], "asn": ["AS64500"], "ns": ["ns1.example.net"], "cert": ["cd34"], "brand": ["paypal"]}
    assert correlate.facts_from_scan({"dns": {"status": "skipped (quick scan)"}, "reasons": []}) == {}


def test_migration_keeps_existing_database_and_backfills_brand():
    path = os.path.join(tempfile.mkdtemp(), "old.db")
    con = sqlite3.connect(path)  # the pre-step-5 schema, no observations table
    con.executescript(
        "CREATE TABLE reporters(id TEXT PRIMARY KEY, reputation REAL NOT NULL DEFAULT 1.0, created REAL NOT NULL);"
        "CREATE TABLE reports(domain TEXT NOT NULL, reporter TEXT NOT NULL, verdict TEXT NOT NULL, url TEXT, note TEXT,"
        " created REAL NOT NULL, PRIMARY KEY(domain, reporter));"
        "CREATE TABLE actions(reporter TEXT NOT NULL, at REAL NOT NULL);"
        "INSERT INTO reporters VALUES('r1', 1.0, 1.0);"
        "INSERT INTO reports VALUES('paypal-login-secure.com','r1','phishing','http://paypal-login-secure.com/','old note',1.0);")
    con.commit()
    con.close()
    i = Intel(path)
    assert i.lookup("paypal-login-secure.com")["threat_reports"] == 1  # old data still readable
    assert i.observations("paypal-login-secure.com")["brand"] == ["paypal"]
    assert Intel(path).observations("paypal-login-secure.com")["brand"] == ["paypal"]  # second open: idempotent
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA user_version").fetchone()[0] == Intel.SCHEMA_VERSION
    con.close()


def test_report_records_the_domain_and_brand_only():
    i = Intel(":memory:")
    _flag(i, "paypa1.xyz")
    obs = i.observations("paypa1.xyz")
    assert obs == {"brand": ["paypal"]}
