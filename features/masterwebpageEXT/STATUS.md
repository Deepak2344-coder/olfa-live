# masterwebpageEXT

**Status:** DONE

## What it is

The **masterwebpageEXT** is a Chrome Manifest V3 extension that combines all of Olfa's
threat-detection and data-sharing-detection capabilities into a single content script.

## Detection Capabilities

| Feature | What it Finds |
|---|---|
| Hidden iframes/overlays | Clickjacking attempts |
| Obfuscated JavaScript | High-entropy scripts & packer patterns |
| Insecure cookies | Missing `Secure` flag |
| Third-party cookies | Tracking across sites |
| Known tracker cookies | Google Analytics, Facebook, etc. |
| Cross-origin credential forms | Password/card forms to other domains or over HTTP |
| Dangerous API usage | `execCommand`, Clipboard API scripts |

## How to Install

```bash
# Load unpacked in Chrome:
chrome://extensions/ → Enable Developer mode → Load unpacked → 
  features/masterwebpageEXT/extension/
```

The content script injects into every page automatically.

## How to Run Tests

```bash
cd features/masterwebpageEXT/extension/content
node --test test-agent.js
# → 8 pass, 0 fail
```

## Result Format

Both `threats` and `dataSharing` arrays contain objects with `type`, `detail`, and optional `domain`.
Score thresholds: **safe** (< 0.4), **suspicious** (0.4–0.75), **dangerous** (≥ 0.75).

## Shared Schema (`risk-schema.js`)

```js
const { reason, makeThreatResult } = require('.../risk-schema.js');
```

- `reason(code, message, severity, details)` → `{ code, message, severity, details }`
- `makeThreatResult(url, score, reasons, collected)` → `{url, score, level, reasons, collected}`

## Experience

Visit any website → Open DevTools → Console → `window.olfaMasterResult` has the detection results.