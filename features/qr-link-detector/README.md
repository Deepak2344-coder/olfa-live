# qr-link-detector

**Status:** DONE

## What it is

The **qr-link-detector** is a Chrome Manifest V3 extension that scans every page you visit for:

1. **QR codes** — image elements (`<img>`) that might contain a QR code, and flags them in the popup
2. **Redirect / shortened links** — links pointing to known URL shorteners (bit.ly, tinyurl, etc.) and links with tracking parameters (UTM, gclid, fbclid, etc.)

The extension uses a lightweight content script that runs on every page. Results are displayed in the extension popup, showing you:
- Possible QR codes found (marked as "possible" since full jsQR library detection would be larger)
- Shortened/redirect links with their domain and risk level
- Tracking parameters detected in URLs

## How to Install

```bash
chrome://extensions/
→ Enable Developer mode
→ Load unpacked
→ Select features/qr-link-detector/extension/
```

The content script auto-injects on every page. Click the extension icon to see the popup.

## How It Works

### QR Code Detection
- Scans all `<img>` and `<canvas>` elements on the page
- Uses heuristics (image size, presence of `src` attribute) to identify *possible* QR code containers
- **Important**: This is a heuristic check — real QR decoding requires the full `jsQR` library (~350KB). This extension uses a lightweight shim to flag *potential* QR code containers. If you need actual QR decoding, the full `jsQR` library can be added later.

### Redirect/Shortened Link Detection
- Checks all `<a href>` links against a hard‑coded list of known shorteners:
  `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, `short.link`, `is.gd`, `buff.ly`, `rebrandly.com`, `bit.do`
- Also flags URLs with suspicious trailing parameters:
  `utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`,
  `gclid`, `fbclid`, `mc_campaign`, `mc_id`
- Each finding shows: display URL (truncated), domain, and severity level

### Severity Levels
- **safe** (< 0.4) — no concerns
- **suspicious** (0.4 – 0.75) — tracking params or unknown shortener
- **dangerous** (≥ 0.75) — known malicious shortener or high-risk tracking

## Popup UI

The popup shows:

| Section | What it Shows |
|---|---|
| **QR Codes** | Count of possible QR code containers, with description and source URL (first 80 chars) |
| **Redirect/Shortened Links** | List of links with: display URL (truncated), severity badge [safe/suspicious/dangerous], domain, and tracking params if any |
| **Status Bar** | Total count and overall severity level |

## Integration for the Core Olfa App

The extension follows the shared risk-schema contract:

```js
// Import from the shared schema (same as other Olfa features)
const { reason, makeThreatResult } = require('features/shared/risk-schema.js');
```

Each finding follows the same shape:
- `code` — e.g., `qr-code`, `redirect-link`, `tracked-link`
- `message` — human-readable description
- `severity` — `high`/`medium`/`low`
- `details` — optional object with `domain`, `rawUrl`, `suspiciousParams`, etc.

The `makeThreatResult(url, score, reasons, collected)` function creates a standardized result object:
- `url` — the page URL that was scanned
- `score` — 0–1 risk score
- `level` — `safe`/`suspicious`/`dangerous`
- `reasons` — array of reason objects
- `collected` — meta info `{qrCodes: n, redirectLinks: m, trackedParams: k}`

## Development / Testing

```bash
# Run the Node unit tests (verify file structure + basic logic)
node --test features/qr-link-detector/tests/detect-test.js
# → 8 pass, 0 fail (tests file structure + JSON parsing)
```

The extension cannot be fully tested in Node because it uses Chrome APIs
(`chrome.runtime.sendMessage`, `chrome.storage.local`). The Node tests
verify the source files contain the expected functions and the manifest
is valid JSON.

## License

MIT — see the project root.