DONE

Feature 3 — redirect-tracer. FastAPI service + timeline UI.

Tests (run from repo root):

    python -m pytest features/redirect-tracer/tests -q
    -> 11 passed in 1.18s

Covered:
  - 3xx chain ending in a meta-refresh (start -> hop2 -> hop3 -> final),
    with the correct status codes and hop kinds
  - literal JS location redirect followed without executing page code
  - redirect loop detection (/loop1 <-> /loop2)
  - hop cap -> too_many_hops
  - private-IP redirect (to http://10.0.0.1) recorded as blocked and never
    fetched, with the allow_hosts escape hatch used only by the test
  - SSRF guard unit tests: 127.0.0.1, localhost, 169.254.169.254, 10.0.0.1,
    file:// all refused
  - compute_flags: shortener, domain hopping, final-domain change,
    https downgrade, clean chain yields no flags
  - risk_score: private target ranks highest, shortener stays low

Not covered: live internet traces (the environment blocks most outbound TLS),
and the browser UI, which is served by the same app and was reviewed by hand.
