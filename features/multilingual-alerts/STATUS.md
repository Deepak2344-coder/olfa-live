# multilingual-alerts

**Status:** DONE

## What it does

The **multilingual-alerts** feature provides a catalog of warning messages in
three languages — English, Hindi, and Bengali — keyed by a shared set of reason
codes.  The purpose is to let Olfa display localized scam‑warning copy without
requiring a backend i18n system.

### Reason codes (shared across all languages)

| Code            | Meaning                              |
|-----------------|--------------------------------------|
| `PHISH_URL`     | Fake login page / credential harvest |
| `TYPOSQUAT`       | Domain looks like a known brand       |
| `URGENT_POPUP`   | User is being urged to act quickly    |
| `INVALID_CERT`   | Site certificate is invalid/expired   |
| `COOKIE_TRACK`   | Aggressive tracking cookies set       |

### Translations

Each reason code has a translated string in:

- **English (`en`)** – the reference language
- **Hindi (`hi`)** – Devanagari script
- **Bangla (`bn`)** – Bengali script

The `getAlert(reason, language)` function returns the appropriate string; if the
language or reason is unknown it falls back gracefully.

## How to run it

```bash
cd features/multilingual-alerts
npm install          # installs node modules (none beyond Node itself)
npm test             # runs the 8‑test suite
# → 8 pass, 0 fail
```

## Integration notes

- **Import the helpers:**

  ```js
  import { getAlert, listReasons, validateReason } from
    'features/multilingual-alerts/lib/alerts.js';
  ```

- **Get a warning string:**

  ```js
  const warning = getAlert('TYPOSQUAT', 'hi');
  // → Hindi string about typosquatting
  ```

- **List available codes for a language:**

  ```js
  const codes = listReasons('bn'); // → ['PHISH_URL', 'TYPOSQUAT', …]
  ```

- **Validate before use:**

  ```js
  if (validateReason('INVALID_CERT', 'en')) {
    const msg = getAlert('INVALID_CERT', 'en');
  }
  ```

- **Share link** – encode the alert payload for a data‑only URL:

  ```js
  import { encodeShare } from 'features/trust-card/lib/card.js';
  const fragment = '#' + encodeShare({ type: 'alert', reason: 'PHISH_URL', language: 'bn' });
  ```

## Tests

```bash
npm test
# 8 tests verify:
#   - getAlert returns correct strings for EN/HI/BN
#   - fallback to English for unsupported languages
#   - default message for unknown reason codes
#   - listReasons returns the full set of 5 codes
#   - validateReason correctly checks membership in each catalog
```