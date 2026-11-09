"""Tests never touch the real network: guarded outbound calls fail unless a test installs its own fake."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    from olfa_core import dnsinfo, feeds, guarded_http
    monkeypatch.setattr(guarded_http, "request",
                        lambda *a, **k: {"status": None, "body": "", "error": "network disabled in tests"})
    dnsinfo._cache.clear()
    feeds._results.clear()
    feeds._default = None
    yield
