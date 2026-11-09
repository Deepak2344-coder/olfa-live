# page-threat-detector

**Status:** DONE

## What it does

The **page-threat-detector** is a Chrome Manifest V3 content script that
injects into every page and detects three common web‑threat techniques:

1. **Hidden iframes / overlays** – elements that are off‑screen, have zero
   width/height, or cover a large portion of the viewport without the user’s
   knowledge (clickjacking).
2. **Obfuscated JavaScript** – scripts with unusually high character entropy or
   known packer patterns (`eval`, `new Function`, `fromCharCode`,
   `arguments.callee`).
3. **Dangerous API usage** – `document.execCommand`, Clipboard API,
   `navigator.clipboard`, and suspicious CSS class names that may indicate
   keystroke or clipboard logging.

The script runs `document_idle` so it does not block page loading.  Detection
results are sent via `chrome.runtime.sendMessage` (or `window.postMessage` as a
fallback) so the extension’s popup or sidebar can display them to the user.

## API (content script)

The content script automatically runs on every page.  It exposes a result via:

- `window.olfaThreatResult` – array of threat objects (set when the script
  runs).  Each object has `type` and `detail` fields.
- `chrome.runtime.sendMessage({ type: 'threats', threats })` – sends the
  result to the extension’s background page.

## API (Node test helper)

The `inspect.js` module in this feature can be used from Node to test the
detection logic without a browser:

```js
import { runDetection } from 'features/page-threat-detector/extension/content/inspect.js';
const threats = runDetection(someText);
```

## How to install (as a Chrome MV3 extension)

1. Load the feature unpacked in Chrome:
   ```bash
   chrome://extensions/
   → Enable Developer mode
   → Load unpacked
   → Select features/page-threat-detector/extension/
   ```
2. The content script will automatically begin scanning pages you visit.
   Results appear in the extension’s popup (if it has a listener) or the
   console.

## How to run the Node tests

```bash
cd features/page-threat-detector
npm install   # no runtime deps beyond Node
npm test
# → 4 pass, 0 fail
```