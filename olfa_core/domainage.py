"""Domain registration age from RDAP (HTTPS, passive, cached).

A domain registered days ago that impersonates a bank is the strongest signal
after the URL itself. Every answer is best-effort: a registry that speaks no
RDAP, a network problem or a missing event yields {"age_days": None} and the
check reports "unknown" instead of guessing.
"""
from __future__ import annotations

import datetime
import time
from typing import Dict, List

import requests

from .schema import reason
from .urlparts import is_ip, registrable

RDAP = "https://rdap.org/domain/"
TIMEOUT = 6.0
TTL = 6 * 3600  # one answer per registrable domain per 6h
CACHE: Dict[str, tuple] = {}
NEW_DAYS = 30      # < 30 days old -> high
YOUNG_DAYS = 180   # < 180 days old -> medium


def lookup(host: str) -> Dict[str, object]:
    """Registration date of host's registrable domain. Never raises."""
    reg = registrable(host) if host else ""
    if not reg or is_ip(reg):
        return {"host": reg, "registered": None, "age_days": None, "source": "rdap", "error": "not_a_domain"}
    now = time.time()
    hit = CACHE.get(reg)
    if hit and now - hit[0] < TTL:
        return hit[1]
    out: Dict[str, object] = {"host": reg, "registered": None, "age_days": None, "source": "rdap", "error": None}
    try:
        resp = None
        sess = requests.Session()
        sess.trust_env = False  # same rule as every other fetch: connect directly, no proxy env
        for verify in (True, False):
            try:
                resp = sess.get(RDAP + reg, timeout=TIMEOUT, verify=verify,
                                headers={"accept": "application/rdap+json, application/json"})
                break
            except requests.exceptions.SSLError:
                continue  # a broken chain must not hide the registration date
        if resp is None:
            out["error"] = "ssl_error"
        elif resp.status_code != 200:
            out["error"] = f"rdap_http_{resp.status_code}"
        else:
            events = resp.json().get("events") or []
            raw = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
            if not raw:
                out["error"] = "no_registration_event"
            else:
                when = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=datetime.timezone.utc)
                days = (datetime.datetime.now(datetime.timezone.utc) - when).days
                if days < 0:
                    out["error"] = "registration_in_the_future"
                else:
                    out["registered"] = when.date().isoformat()
                    out["age_days"] = days
    except Exception as exc:  # noqa: BLE001 - the app must run without a WHOIS/RDAP answer
        out["error"] = f"{type(exc).__name__}: {exc}"[:160]
    CACHE[reg] = (now, out)
    if len(CACHE) > 500:
        CACHE.pop(next(iter(CACHE)))
    return out


def reasons(info: Dict[str, object]) -> List[dict]:
    """Turn an age answer into threat reasons (nothing when unknown or old)."""
    age = info.get("age_days")
    if not isinstance(age, int):
        return []
    reg, date = info.get("host"), info.get("registered")
    if age < NEW_DAYS:
        return [reason("new_domain", f"The domain {reg} was registered only {age} days ago ({date}); "
                                     "brand-new domains are very often used for phishing.", "high",
                       {"age_days": age, "registered": date}, "threat")]
    if age < YOUNG_DAYS:
        return [reason("new_domain", f"The domain {reg} was registered {age} days ago ({date}), which is recent.",
                       "medium", {"age_days": age, "registered": date}, "threat")]
    return []
