# page-inspector — what is this site taking from you?

A Chrome (MV3) extension with a popup that shows, for the current tab: cookies,
outgoing requests, forms, storage keys and device-fingerprinting calls — then
turns them into the shared risk score + reasons.

## Privacy promise (read this first)

**Everything stays on your machine.**

- Cookie **values are dropped before anything else happens** — the popup shows
  name, domain, flags, expiry only. There is a test that fails if a value ever
  leaks into the result object.
- The background worker stores URL + method + resource type only. No headers, no
  request bodies, no response data.
- Form fields are described by name/type/autocomplete — **never their values**.
- No network calls at all. There is no endpoint, no telemetry, no third-party
  script.

## What it shows

Four tabs, plus a risk score in the header.

| Tab | Source | Signals raised |
| --- | --- | --- |
| **Cookies** | `chrome.cookies` | `cookies_missing_secure`, `third_party_cookies`, `known_tracker` |
| **Requests** | `chrome.webRequest` (observe only) | `many_third_parties` (≥8 domains), `known_tracker`, `cross_origin_posts` |
| **Forms** | content script | `credential_form_cross_origin`, `credentials_over_http` |
| **Storage** | content script | `fingerprinting` (canvas/audio/permissions), `local_storage_keys` count |

Third-party cookies and cross-origin POSTs are coloured so they are obvious at a
glance. The bundled tracker list (`KNOWN_TRACKERS` in
`extension/lib/signals.js`) covers the usual ad/analytics suspects.

## Run the demo

```bash
# demo page + fake third-party tracker (no dependencies)
node features/page-inspector/demo/server.js
# -> http://127.0.0.1:8791/

# chrome://extensions -> Developer mode -> Load unpacked ->
#   features/page-inspector/extension

# open the demo page, then click the Olfa toolbar icon.
# For the Requests tab, load the page with the popup closed first (the worker
# records as requests happen), then open the popup.
```

The demo page triggers every signal it can locally: an insecure cookie, a
tracker script and a POST beacon from `localhost` (a different host from
`127.0.0.1`, so it is genuinely third-party), a password form posting to the
tracker host, two storage keys and a `canvas.toDataURL()` fingerprint read.

## Tests

```bash
node --test features/page-inspector/tests/signals.test.js   # 9 tests
```

The judgement logic is pure (`analyze(facts)`), so tests feed it plain JSON:
clean page, insecure cookies, tracker cookies, cross-origin credential forms,
http credentials, card fields, many third parties + trackers + POSTs,
fingerprinting, and schema conformance of every reason.

## Integrating into the core app

`extension/lib/signals.js` is dependency-free and exports one function:

```js
const { analyze } = require('./features/page-inspector/extension/lib/signals.js');

const { result, signals } = analyze({
  pageUrl: 'https://shop.example/',
  cookies: [{ name: 'sid', domain: '.doubleclick.net', secure: false }],
  requests: [{ url: 'https://doubleclick.net/p.gif', method: 'GET' }],
  forms: [{ action: 'https://collector.example/login', fields: [{ name: 'password', type: 'password' }] }],
  storageKeys: { local: ['uid'], session: [] },
  fingerprintCalls: ['canvas'],
});

// result -> shared schema {url, score, level, reasons[]}
// signals -> { known_tracker_cookies: 1, credential_form_cross_origin: true, ... }
```

`signals` is the part the core app wants as **extra scoring features**; `result`
is the human-facing explanation. Type shapes are documented in the JSDoc above
`analyze`.

## Known limits

- Request history is per tab and cleared on navigation; it does not survive a
  browser restart (stored in `chrome.storage.session` on purpose).
- Fingerprinting hooks must load before the page's own scripts; a fingerprint
  taken in the first milliseconds of `document_start` can be missed.
- `chrome.cookies` returns values from the extension's own partition view, not
  the exact bytes a site saw.
- The tracker list is a bundled heuristic, not a maintained blocklist.
