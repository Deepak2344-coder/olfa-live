# masterwebpageEXT

**Status:** DONE

## What it is

The **masterwebpageEXT** is a Chrome Manifest V3 extension that combines all of Olfa's
threat-detection and data-sharing-detection capabilities into a single content script.

Instead of running separate extensions, you can load this one extension to get:

| Detection Capability | What it Finds |
|---|---|
| **Hidden iframes / overlays** | Clickjacking attempts — elements off‑screen or covering the viewport |
| **Obfuscated JavaScript** | High‑entropy scripts & known packer patterns (`eval`, `new Function`, `fromCharCode`) |
| **Insecure cookies** | Cookies without the `Secure` flag — can leak over plain HTTP |
| **Third‑party cookies** | Cookies from other domains that can follow you across sites |
| **Known tracker cookies** | Google Analytics, Facebook, Hotjar, Mixpanel, and other tracking domains |
| **Cross‑origin credential forms** | Password/card forms posting to another domain or over plain HTTP |
| **Dangerous API usage** | Scripts accessing `document.execCommand`, Clipboard API |

## How to Install (as a Chrome MV3 Extension)

1. Load unpacked in Chrome:
   ```bash
   chrome://extensions/
   → Enable Developer mode
   → Load unpacked
   → Select features/masterwebpageEXT/extension/
   ```

2. The content script automatically injects into every page you visit.

3. Open Chrome DevTools → Console → you'll see:
   - `window.olfaMasterResult` → `{ threats: [], dataSharing: [] }`
   - Or, if threats are found, the console logs will list them.

## How to Run Tests (Node)

```bash
cd features/masterwebpageEXT/extension/content
node --test test-agent.js
# → 8 pass, 0 fail
```

## What Each Detection Does

### Hidden iframes & overlays
- Finds iframes with `width=0` or `height=0`, or elements covering >50% of the viewport
- Flags them as potential clickjacking

### Obfuscated JavaScript
- Computes a ratio of unique characters to total characters
- Flags if ratio > 0.75 (high entropy)
- Also flags known packing patterns: `eval()`, `new Function`, `fromCharCode`, `arguments.callee`

### Cookie analysis (via `chrome.cookies.getAll`)
- **Insecure cookies** — missing the `Secure` flag
- **Third‑party cookies** — from domains different from the current page
- **Known tracker cookies** — from a hard‑coded list of tracking domains
- **HttpOnly cookies** — noted for server‑only access

### Cross‑origin credential forms
- Detects password/card forms that:
  - Post to a different domain (cross‑origin)
  - Submit over plain HTTP (no encryption)
  - Contain fields named `password`, `cc-number`, `cvv`, etc.

### Dangerous API usage
- Flags scripts containing `execCommand`, `clipboard.write`, or `navigator.clipboard`

## Result Format

Both **threats** and **dataSharing** arrays contain objects with:
- `type` — the kind of finding (`hidden-iframe`, `insecure-cookie`, etc.)
- `detail` — a human‑readable description
- `domain` — the domain the finding relates to (when applicable)

The shared risk schema (`risk-schema.js`) provides:
- `reason(code, message, severity, details)` → creates a reason object
- `makeThreatResult(url, score, reasons, collected)` → creates a `{url, score, level, reasons, collected}` result
- Score thresholds: **safe** (< 0.4), **suspicious** (0.4–0.75), **dangerous** (≥ 0.75)

## Integration Notes for the Core Olfa App

The core app can import the shared schema:

```js
const { reason, makeThreatResult } = require('features/masterwebpageEXT/extension/content/risk-schema.js');
```

The `analyze`-style logic from other features (e.g., `page-inspector/extension/lib/signals.js`) follows the same contract:
- Input: `{pageUrl, cookies, requests, forms, storageKeys, fingerprintCalls}`
- Output: `{ result: {url, score, level, reasons, collected}, signals }`

Each reason has: `code`, `message`, `severity` (`high`/`medium`/`low`), and optional `details` with domain/name info.

## License

MIT — see the project root.