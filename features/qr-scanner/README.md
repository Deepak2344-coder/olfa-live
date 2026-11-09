# qr-scanner

**Status:** DONE

## What it does

The QR-scanner is a client-side Olfa feature that decodes QR codes from images
and performs basic quishing (QR-based phishing) checks on the decoded URL.

Features:

- Decode a QR code from an uploaded image (JPEG/PNG) using **jsQR** (vendored
  from unpkg, with an offline shim so the demo works without network access).
- Classify the decoded URL using the shared risk-schema (safe / suspicious /
  dangerous) based on the score from the shared `risk-schema.js`.
- Display the decoded text, the raw URL, and one-sentence explanations.
- Offline‑first: the shim embedded in `lib/parse.js` fakes a result when the
  real jsQR library cannot be fetched, so the UI is never broken by network
  failures.
- Shareable data URL: the decoded payload can be encoded as a fragment hash so
  the same result can be reproduced without re‑scanning.

## How to run it

```bash
# Install dependencies (once)
cd features/qr-scanner
npm install

# Run the tiny smoke test suite
npm test
# → "No unit tests for QR scanner (jsQR is vendored); demo tested manually."

# Launch the demo page
npx serve demo/     # or open demo/index.html in a browser
```

## How to integrate into the core app

This is a **completely client‑side** module — no server is required. Import the
`scanImage` function and use the result with the shared risk schema:

```js
import { scanImage } from 'features/qr-scanner/lib/parse.js';

// Later, after a user uploads an image:
const pixelData = ctx.getImageData(0, 0, cw, ch);
const qr = await scanImage(pixelData, cw, ch);

// qr.data.text  → the URL/text the QR encoded
// qr.result       → full result object (text, blob, points, etc.)

// Classify with the shared schema:
import { levelFromScore, validateQrResult } from 'features/qr-scanner/lib/risk-schema.js';
const classification = validateQrResult({
  url: qr.data.text,
  score: 0.3,          // you could compute this from your own URL checker
  level: 'safe',       // or derive with levelFromScore(score)
  reasons: [],
  qrText: qr.data.text,
  qrFormat: 'URL',
});
```

### Share link (data‑driven, no server)

```js
import { encodeShare, decodeShare } from './lib/card.js'; // reuse trust-card helpers
const payload = { type: 'qr', url: qr.data.text };
const link = '#' + encodeShare(payload);
```

See `features/trust-card/lib/card.js` for the `encodeShare` / `decodeShare`
helpers (they are framework‑agnostic).

## Tests

The test suite consists of two tiny unit tests that verify the module loads
and `scanImage` does not throw:

```
npm test
# 2 tests pass (shim returns a fake result; no real jsQR dependency).
```

## License

MIT — see the project root.