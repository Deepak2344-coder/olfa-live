# message-analyzer

**Status:** DONE

## What it does

The message‑analyzer scans pasted SMS, email, or WhatsApp text for common scam
patterns.  It supports three languages (English, Hindi, Bengali) and uses a
set of RegEx‑based rules to flag urgent language, brand impersonation, gift‑card
scams, credential harvesting (OTP), and "too good to be true" offers.

The UI highlights the matched spans with `<mark>` tags and reports how many
signals were found.

## How to run it

```bash
cd features/message-analyzer
npm install          # installs node modules (none beyond Node itself)
npm test             # runs the 7‑test suite
# → 7 pass, 0 fail

npx serve demo/      # or open demo/index.html in a browser
```

## Integration notes

- **Import the functions:**

  ```js
  import { analyze, highlighted } from 'features/message-analyzer/lib/rules.js';
  ```

- **Analyze a message:**

  ```js
  const matches = analyze("URGENT: Verify your OTP 123456", "en");
  // → [{span: "URGENT", label: "urgent language", start: 0}, …]
  ```

- **HTML‑ready highlighted spans:**

  ```js
  const { highlighted } = highlighted("URGENT: Verify your OTP", "en");
  // → 'Verify your <mark>OTP</mark>' plus surrounding text
  ```

- **Sample messages** – load from the example JSONs:

  ```js
  import en from './features/message-analyzer/examples/en1.json';
  analyze(en.text, 'en');
  ```

## Tests

```bash
npm test
# 7 tests cover:
#   - EN urgent language detection
#   - EN brand impersonation
#   - EN credential harvesting (OTP)
#   - HI rule on Hindi text
#   - BN rule on Bangla text
#   - HTML highlight rendering with <mark>
#   - No false positives on a safe message
```