DONE

Feature 2 — page-inspector. Chrome MV3 extension (cookies, requests, forms,
storage, fingerprinting) + demo page/server.

Tests (run from repo root):

    node --test features/page-inspector/tests/signals.test.js
    -> 9 tests, 9 pass, 0 fail

Covered:
  - clean first-party page: no reasons, safe level, score 0
  - insecure cookie vs third-party cookie vs known-tracker cookie counted
    separately
  - cookie values never appear in the result object (privacy assertion)
  - cross-origin password form -> credential_form_cross_origin, high, and the
    page no longer scores as safe
  - http credential form -> credentials_over_http even when same-origin
  - card-number field counts as a secret
  - 11 third-party hosts + tracker + cross-origin POST reach the suspicious band
  - fingerprinting (canvas + audio) raises its medium signal and compounds with
    trackers
  - every reason validates against features/shared/schema.json

Two fixes made while testing:
  - a single high-severity finding used to total 0.38 (below the 0.4 line);
    raised to 0.45 so a cross-origin credential form is never "safe"
  - medium weight 0.16 -> 0.18 so several medium signals actually accumulate

Not covered by automated tests (needs Chrome): popup rendering, the four tabs,
chrome.cookies/webRequest collection and the demo page. Steps are in README.md.
