DONE

Feature 1 — realtime-blocking. Chrome MV3 extension + mock scan server + demo pages.

Tests run from the repo root:

    node --test features/realtime-blocking/tests/tier.test.js
    -> 11 tests, 11 pass, 0 fail (duration ~340 ms)

What the tests cover:
  - tier boundaries: 0.95/0.91 -> block, 0.90/0.40 -> warn, 0.39 -> log
  - whitelist override (gov.in, .edu, ac.in, top brands) and that
    google.com.evil.example is NOT whitelisted
  - blocklist host + subdomain matching
  - typosquat: paypa1.com flagged, paypal.com/google.co.in clean,
    brand-as-subdomain (paypal.login-secure.xyz) flagged
  - every heuristic code fires on its trigger URL, clean URL raises no
    high-severity signal
  - localCheck end-to-end: block / allow / warn / log tiers
  - every emitted reason satisfies features/shared/schema.json

Not covered by automated tests (needs a real browser):
  - chrome.webNavigation navigation interception
  - the notification + Undo flow
  - content-script banner injection and cross-domain form blocking
  Demo steps for those are in README.md and were reviewed by hand.
