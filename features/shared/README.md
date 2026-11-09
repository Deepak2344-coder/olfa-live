# features/shared — the contract every Olfa feature speaks

Nothing in this folder runs on its own. It is the glue: one risk-score shape,
helpers to build and check it, and the Hachi placeholder asset.

## The risk-score object

Every feature returns (or embeds) this object. JSON Schema: [`schema.json`](./schema.json).

```json
{
  "url": "https://paypa1-login.example/verify",
  "score": 0.93,
  "level": "dangerous",
  "reasons": [
    {
      "code": "typosquat",
      "message": "The domain imitates paypal.com but is not paypal.com.",
      "severity": "high",
      "details": { "brand": "paypal", "distance": 1 }
    }
  ]
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `url` | string | What was scored. A URL, a domain, or a message id — features document theirs. |
| `score` | number 0–1 | Risk. `0` harmless, `1` certainly malicious. |
| `level` | `safe` \| `suspicious` \| `dangerous` | Derived from `score`, never set by hand. |
| `reasons` | array | Empty array means "nothing suspicious found" — not an error. |
| `reasons[].code` | string | Stable snake_case key. **This is the i18n key** used by `features/multilingual-alerts`. |
| `reasons[].message` | string | One plain sentence for humans. |
| `reasons[].severity` | `low` \| `medium` \| `high` | Defaults to `medium`. |
| `reasons[].details` | object | Feature-specific extras. Optional. |

Extra top-level keys are allowed (`additionalProperties: true`) so a feature can
add its own payload — `features/redirect-tracer` adds `hops`, `trust-card` adds
`card`, and so on. Consumers must ignore keys they do not know.

### Score → level thresholds

| score | level |
| --- | --- |
| `0.00 – 0.3999` | `safe` |
| `0.40 – 0.7499` | `suspicious` |
| `0.75 – 1.00` | `dangerous` |

These exact numbers live in `THRESHOLDS` in both helper files. Change them in one
place only if you change them everywhere, and update this table.

### Reason codes already in use

`typosquat`, `new_domain`, `blocklisted`, `brand_impersonation`,
`credential_form_cross_origin`, `credentials_over_http`, `cookies_missing_secure`,
`many_third_parties`, `known_tracker`, `too_many_hops`, `shortener_used`,
`domain_hopping`, `https_downgrade`, `final_domain_differs_from_origin`,
`bad_certificate`, `expiring_certificate`, `self_signed_certificate`,
`upi_scam`, `fake_kyc`, `lookalike_gov_portal`, `urgency_language`,
`payment_request`, `hidden_iframe`, `clickjacking_overlay`, `obfuscated_script`,
`keystroke_exfiltration`, `clipboard_hijack`, `risky_permission_request`,
`qr_risky_payload`, `redirect_loop`, `blocked_private_address`.

Codes are a public contract: `features/multilingual-alerts` must have a
translation for every one of them, and its lint script fails the build otherwise.

## Helpers

**JavaScript** — [`risk-schema.js`](./risk-schema.js) is a classic script (no
bundler, no imports) that attaches `OlfaSchema` to the global object, and also
exports itself through `module.exports` for Node tests.

```js
// MV3 service worker
importScripts('../shared/risk-schema.js');
const result = OlfaSchema.makeResult(url, 0.93, [
  OlfaSchema.reason('typosquat', 'Imitates paypal.com.', 'high', { brand: 'paypal' }),
]);
```

```js
// Node test
const OlfaSchema = require('../../shared/risk-schema.js');
assert.deepStrictEqual(OlfaSchema.levelFromScore(0.75), 'dangerous');
```

**Python** — [`risk_schema.py`](./risk_schema.py) mirrors it exactly.

```python
from features.shared.risk_schema import make_result, reason
make_result("https://x.example", 0.93, [reason("typosquat", "Imitates paypal.com.", "high")])
```

Both expose `clampScore/clamp_score`, `levelFromScore/level_from_score`,
`reason`, `makeResult/make_result` and `validateResult/validate_result`.

## Assets

`assets/hachi.png` is a **placeholder** Shiba illustration standing in for the
real Hachi mascot. Every feature references it by that exact path. Drop the real
artwork over it — same filename, square, transparent background preferred — and
every feature picks it up with no code change.

## Conventions for feature authors

1. Never edit outside `features/` (repo rule from `AGENTS.md`).
2. One folder per feature, with `README.md`, a runnable demo, and tests.
3. Reasons carry a `code`; codes get an entry in `multilingual-alerts`.
4. No secrets. If something needs a key, it goes in a `.env.example` and the
   feature must still work without it (rule-based or mock fallback).
5. Free tiers only.
