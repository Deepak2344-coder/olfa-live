"""Tests for redirect-tracer. No internet needed: everything runs against a
local mock HTTP server, and the flag rules are tested as pure functions."""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tracer import check_url, compute_flags, is_shortener, risk_score, trace  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    """A tiny redirect playground."""

    def log_message(self, *args):  # keep pytest output clean
        pass

    def _redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("location", location)
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        path = self.path
        if path == "/start":
            return self._redirect("/hop2")
        if path == "/hop2":
            return self._redirect("/hop3")
        if path == "/hop3":
            # markup redirect instead of a 3xx
            body = b'<html><head><meta http-equiv="refresh" content="0; url=/final"></head></html>'
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if path == "/js":
            body = b"<script>window.location.href = '/final';</script>"
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if path == "/final":
            body = b"<html><body>destination</body></html>"
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if path == "/loop1":
            return self._redirect("/loop2")
        if path == "/loop2":
            return self._redirect("/loop1")
        if path.startswith("/many"):
            # /many0 -> /many1 -> ... -> /many12
            index = int(path.replace("/many", ""))
            if index >= 12:
                body = b"<html>end</html>"
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            return self._redirect(f"/many{index + 1}")
        if path == "/to-private":
            return self._redirect("http://10.0.0.1/nothing")
        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


# --------------------------------------------------------------------- trace


def test_follows_header_redirects_then_meta_refresh(server):
    result = trace(server + "/start", allow_private=True)
    assert result.error is None
    urls = [hop.url for hop in result.hops]
    assert urls == [server + "/start", server + "/hop2", server + "/hop3", server + "/final"]
    assert [hop.status for hop in result.hops] == [302, 302, 200, 200]
    assert result.hops[2].kind == "meta_refresh"
    assert result.final_url == server + "/final"


def test_follows_literal_js_redirect_without_executing_it(server):
    result = trace(server + "/js", allow_private=True)
    assert result.final_url == server + "/final"
    assert any(hop.kind == "js" for hop in result.hops)


def test_detects_redirect_loop(server):
    result = trace(server + "/loop1", allow_private=True)
    assert "redirect_loop" in result.flags
    assert result.error is None


def test_hop_cap_produces_too_many_hops(server):
    result = trace(server + "/many0", allow_private=True, max_hops=5)
    assert len(result.hops) <= 6
    assert "too_many_hops" in result.flags


def test_private_address_redirect_is_blocked(server):
    """First hop allowed explicitly, the redirect into 10.x must be refused."""
    result = trace(server + "/to-private", allow_hosts=["127.0.0.1"])
    assert "blocked_private_address" in result.flags
    assert result.error and "private address" in result.error
    # The blocked hop is recorded, and never fetched.
    assert result.hops[-1].kind == "blocked"
    assert result.hops[-1].status is None


def test_ssrf_guard_rejects_loopback_and_metadata_ip():
    assert check_url("http://127.0.0.1/") is not None
    assert check_url("http://localhost:8080/") is not None
    assert check_url("http://169.254.169.254/latest/meta-data/") is not None
    assert check_url("file:///etc/passwd") is not None
    assert check_url("http://10.0.0.1/") is not None
    # An explicit allow-list is the only way through (used by the tests above).
    assert check_url("http://127.0.0.1/", allow_hosts=["127.0.0.1"]) is None


# ------------------------------------------------------- pure flag computation


def hop(url, **over):
    entry = {"url": url, "status": 302, "domain": url.split("/")[2] if "//" in url else "", "shortener": False,
             "kind": "http", "error": None}
    entry.update(over)
    return entry


def test_compute_flags_shortener_and_domain_hop():
    hops = [hop("https://bit.ly/abc", shortener=True), hop("https://evil.example/login")]
    flags = compute_flags(hops, "https://bit.ly/abc", "https://evil.example/login")
    assert "shortener_used" in flags
    assert "domain_hopping" in flags
    assert "final_domain_differs_from_origin" in flags


def test_compute_flags_https_downgrade():
    hops = [hop("https://bank.example/a"), hop("http://bank.example/b")]
    assert "https_downgrade" in compute_flags(hops, hops[0]["url"], hops[1]["url"])


def test_compute_flags_clean_chain_has_no_flags():
    hops = [hop("https://shop.example/a"), hop("https://shop.example/b")]
    assert compute_flags(hops, hops[0]["url"], hops[-1]["url"]) == []


def test_shortener_list_matching():
    assert is_shortener("https://bit.ly/x")
    assert is_shortener("https://www.tinyurl.com/y")
    assert not is_shortener("https://bit.ly.evil.example/x")
    assert not is_shortener("https://example.com/x")


def test_risk_score_ranks_private_target_highest():
    assert risk_score([], ["blocked_private_address"]) >= 0.9
    assert risk_score([], ["shortener_used"]) < 0.2
    assert risk_score([], []) == 0
