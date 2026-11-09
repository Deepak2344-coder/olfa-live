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

### API

```js
import { getAlert, listReasons, validateReason } from 'features/multilingual-alerts/lib/alerts.js';

// Get a localized warning string:
const enText = getAlert('PHISH_URL', 'en');
// → 'Warning: This page impersonates a login screen.'

const hiText = getAlert('PHISH_URL', 'hi');
// → 'चेतावनी: यह पृष्ठ लॉगिन स्क्रीन की नकल कर रहा है。'

const bnText = getAlert('PHISH_URL', 'bn');
// → 'সতর্কতা: এই পৃষ্ঠাটি লগইন স্ক্রিনের নকল।'

// List all reason codes for a language:
const codes = listReasons('en'); // → ['PHISH_URL', 'TYPOSQUAT', ...]

// Validate a reason code exists in a language catalog:
const valid = validateReason('PHISH_URL', 'en'); // → true
```

### Share link (data‑driven)

The warning text can be encoded into a URL fragment for sharing:

```js
import { encodeShare, decodeShare } from 'features/trust-card/lib/card.js';
const payload = { type: 'alert', reason: 'PHISH_URL', language: 'bn' };
const fragment = '#' + encodeShare(payload);
```

See `features/trust-card/lib/card.js` for the shared `encodeShare` /
`decodeShare` helpers.

## How to run it

```bash
# Install dependencies (once)
cd features/multilingual-alerts
npm install

# Run the unit test suite
npm test
# → 8 pass, 0 fail
```

## Tests

```bash
npm test
# 8 tests cover:
#   - EN getAlert for PHISH_URL
#   - HI getAlert for TYPOSQUAT
#   - BN getAlert for INVALID_CERT
#   - Fallback to English for unknown language
#   - Default message for unknown reason code
#   - listReasons returns 5 codes for EN/HI/BN
#   - validateReason in EN, HI, BN
```

## License

MIT — see the project root.