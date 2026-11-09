# Olfa — extra features

Add-on features for **Olfa**, an AI-powered web threat detection and digital
trust platform. Mascot: **Hachi**, a Shiba.

Everything here is deliberately standalone. Each folder is a self-contained
module with its own README, demo and tests, and a documented interface
(an HTTP endpoint, an importable function, or a Chrome extension) so the core
app can adopt it later without assuming its stack.

> Built by the features track. The core site is owned by a different track —
> nothing in this folder is imported by the core app yet.

## Start here

- [**`shared/`](./shared/README.md)** — the one risk-score shape every feature
  speaks, plus the Hachi placeholder at `shared/assets/hachi.png`.
- Each feature's `README.md` documents its own JSON in/out and integration steps.

## Status

| # | Feature | What it does | Kind | Status |
|---|---|---|---|---|
| 1 | [realtime-blocking](./realtime-blocking/) | Blocks or warns on navigation, auto-closes risky popup tabs, logs everything | Chrome MV3 extension | DONE |
| 2 | [page-inspector](./page-inspector/) | Popup showing cookies, third-party requests, forms and storage a site touches | Chrome MV3 extension | DONE |
| 3 | [redirect-tracer](./redirect-tracer/) | Follows a URL's redirect chain safely and flags shorteners, downgrades, hops | FastAPI + web UI | DONE |
| 4 | [trust-card](./trust-card/) | Turns a scan into a shareable "nutrition label" trust card (HTML/PNG/link) | Static web app | DONE |
| 5 | [qr-scanner](./qr-scanner/) | Client-side QR decoding and quishing checks (URLs, UPI, WiFi, vCard) | Static web app | DONE |
| 6 | [message-analyzer](./message-analyzer/) | Scans pasted SMS/email/WhatsApp text for scams with highlighted spans | FastAPI + web UI | DONE |
| 7 | [multilingual-alerts](./multilingual-alerts/) | Warning copy in English, Hindi and Bengali keyed by reason code | JS library + demo | DONE |
| 8 | [cert-chain-3d](./cert-chain-3d/) | Interactive 3D visualisation of a site's TLS certificate chain | Python helper + Three.js | DONE |
| 9 | [brand-matcher](./brand-matcher/) | Detects pages that visually imitate a brand but live on the wrong domain | Python CLI + HTTP | DONE |
| 10 | [n8n-takedown](./n8n-takedown/) | n8n workflow that drafts and files phishing reports (dry-run by default) | n8n workflow JSON | DONE |
| 11 | [page-threat-detector](./page-threat-detector/) | Content script that finds clickjacking, obfuscated JS and hijack patterns | Chrome MV3 extension | DONE |
| 12 | [qr-link-detector](./qr-link-detector/) | Chrome MV3 extension that detects QR code candidates and redirect/shortened links; flags them in a popup | Chrome MV3 extension | DONE |

Status legend: `DONE` (demo + tests pass), `🚧 building`, `—` not started.

Each feature also carries a `STATUS.md` with the commands that were run.

## Running all tests

```bash
# Node tests (run from repo root)
node --test features/realtime-blocking/tests/tier.test.js
node --test features/page-inspector/tests/signals.test.js
node --test features/trust-card/tests/grade.test.js

# Python tests
python -m pytest features/redirect-tracer/tests -q
python -m pytest features/message-analyzer/tests -q
python -m pytest features/multilingual-alerts/tests -q
python -m pytest features/cert-chain-3d/tests -q
python -m pytest features/brand-matcher/tests -q
python -m pytest features/n8n-takedown/tests -q
python -m pytest features/page-threat-detector/tests -q

# Node tests
node --test features/qr-link-detector/tests/detect-test.js
```

## Integration notes per feature

| Feature | Integration hook |
|---|---|
| `realtime-blocking` | Extend the MV3 service worker `sw.js` tier logic; the `BLOCKLIST` and `typosquat` function are imported from `features/realtime-blocking/extension/lib/tier.js` |
| `page-inspector` | The `analyze(facts)` function from `features/page-inspector/extension/lib/signals.js` returns `{result, signals}` and deliberately drops cookie values for privacy |
| `redirect-tracer` | The `trace()` function from `features/redirect-tracer/app.py` returns `{url, flags, risk_score, redirect_chain}`; `shorteners.json` lists known URL shorteners |
| `trust-card` | Import `computeGrade(input)` from `features/trust-card/lib/grade.js` — returns `{grade, points, verdict, sections, highlights, domain}`. The card can be rendered via `renderCard(container, input)` from `features/trust-card/lib/card.js` or exported as PNG via `html-to-image` |
| `qr-scanner` | The client-side `lib/parse.js` wraps `jsQR` (vendored from unpkg). Demo page `demo/index.html` shows live scan results; offline mock mode available |
| `message-analyzer` | FastAPI `POST /analyze` accepts `{text: string}` and returns `{results: [{span, label, hi, lo}]}`. Sample messages in `examples/` cover EN/HI/BN. `.env.example` documents the `OLFA_RULES_PATH` path |
| `multilingual-alerts` | Catalog `locales/{en,hi,bn}.json` maps reason codes to translated warning strings. `getAlert(reason)` returns the localized string. The lint script checks that every reason code used in the codebase has a translation |
| `cert-chain-3d` | Python script `chain.py` fetches a TLS chain via `ssl`/`cryptography`, outputs a `health` colour. The Three.js visualisation uses three preset colour schemes (green/yellow/red) and a 2D fallback mode |
| `brand-matcher` | Python CLI `detect.py` takes a reference image hash and a directory, outputs any visual mismatches. The HTTP endpoint at `/match` accepts a POST with an image file and returns brand/domain mismatches |
| `n8n-takedown` | `workflow.json` is a valid n8n workflow JSON. Set `DRY_RUN=true` (default) to generate only the draft report; `DRY_RUN=false` sends it via the mock sender. The test suite validates the workflow shape |
| `qr-link-detector` | Content script scans page for QR code candidates and redirect/shortened links; results displayed in popup. Import `reason` / `makeThreatResult` from `features/qr-link-detector/extension/content/risk-schema.js` for shared contract |
| `page-threat-detector` | MV3 content script detects: (a) hidden iframes/overlays, (b) obfuscated JS, (c) keystroke/clipboard/permission abuse. Each technique has a demo page under `demo/`. The `detect(contentDocument)` function returns `{threats: []}` |

## Prompt 0 done