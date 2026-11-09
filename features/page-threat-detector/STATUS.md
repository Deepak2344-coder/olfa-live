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

## How to run it

```bash
cd features/page-threat-detector
npm install   # no runtime deps beyond Node
npm test      # runs the 4‑test suite
# → 4 pass, 0 fail
```

### Load as a Chrome extension

```bash
# In chrome://extensions/:
→ Enable Developer mode
→ Load unpacked
→ Select features/page-threat-detector/extension/
```

The content script will begin scanning pages you visit.  Detected threats are
available via `window.olfaThreatResult` or by listening to
`chrome.runtime.onMessage`.

### Node testing

```js
import { runDetection } from 'features/page-threat-detector/extension/content/inspect.js';
const threats = runDetection(someText);
```