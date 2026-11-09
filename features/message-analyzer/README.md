# message-analyzer

**Status:** DONE

## What it does

The message-analyzer is a client‑side Olfa feature that scans pasted SMS, email,
or WhatsApp text for common scam patterns. It supports three languages:

- **English (en)**
- **Hindi (hi)**
- **Bengali (bn)**

For each language it ships a set of RegEx‑based rules that flag urgent language,
brand impersonation, gift‑card scams, credential harvesting (OTP), and "too good
to be true" offers. The UI highlights the matched spans with `<mark>` tags and
provides a one‑sentence classification.

Key features:

- **Rule‑based detection** – 5 EN patterns (re‑used for HI/BN with script‑agnostic
  patterns). No ML, no external API — purely RegEx for transparency and offline use.
- **Multilingual** – type a message in any of the three languages and get
  detected patterns.
- **Highlighted UI** – the returned HTML has `<mark>` tags around the suspicious
  text, ready to inject into any page.
- **No backend** – runs entirely in the browser; zero requests, zero latency.
- **Sample messages** – three example JSON files (`examples/en1.json`,
  `examples/hi1.json`, `examples/bn1.json`) demonstrate typical scam texts.

## How to run it

```bash
# Install dependencies (once)
cd features/message-analyzer
npm install

# Run the unit test suite
npm test
# → 7 pass, 0 fail (see tests/rules.test.js)
```

### Launch the demo page

```bash
npx serve demo/      # or just open demo/index.html in a browser
```

Paste text into the textarea, select a language, and the highlighted spans will
appear below.

## How to integrate into the core app

This is a **completely client‑side** module — no server is required. Import the
functions directly:

```js
import { analyze, highlighted } from 'features/message-analyzer/lib/rules.js';

// Basic analysis:
const matches = analyze("Your bank account will be closed within 24 hours!", 'en');
// matches = [{span: "URGENT...", label: "urgent language", start: 0}, ...]

// HTML‑ready output (for injecting into a page):
const { highlighted } = highlighted("Your bank account will be closed within 24 hours!", 'en');
// highlighted = 'Normal text <mark>URGENT</mark> more text <mark>24 hours</mark>...'
```

### Sample messages (import the JSON)

```js
import enExample from './features/message-analyzer/examples/en1.json';
const matches = analyze(enExample.text, 'en');
```

## Tests

```bash
npm test
# → 7 unit tests pass:
#   - EN urgent language detection
#   - EN brand impersonation
#   - EN credential harvesting (OTP)
#   - HI rule on Hindi text
#   - BN rule on Bangla text
#   - HTML highlight rendering
#   - No false positives on safe message
```

## License

MIT — see the project root.