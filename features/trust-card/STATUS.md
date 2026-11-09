# trust-card

**Status:** DONE

## What it does

The trust-card is a standalone Olfa feature that turns a domain-scan payload into a
letter-grade (A–F) "nutrition label" for website trustworthiness. It produces:

- One overall letter grade (A = most trustworthy, F = dangerous)
- Six section grades: overall risk, certificate, domain age, security headers,
  cookie hygiene, community reports
- One-sentence verdict and highlighted concerns
- A data URL share link (embed the whole card in the fragment hash, no server
  needed)

The output can be rendered as HTML, exported as a PNG via `html-to-image`, or
shared as a plain JSON payload.

## How to run it

```bash
# Install dependencies (once)
cd features/trust-card
npm install          # installs node modules listed in package.json

# Run the unit tests
node --test tests/grade.test.js
# → 9 pass, 0 fail

# Quick demo (renders a card for the "safe" example into #card div)
node -e "
const { renderCard, computeGrade } = require('./lib/grade.js');
const fs = require('fs');
const input = JSON.parse(fs.readFileSync('examples/safe.json','utf8'));
const container = document.createElement('div');
const result = computeGrade(input);
console.log('Grade:', result.grade);
console.log('Verdict:', result.verdict);
"
```

## How to integrate into the core app

This module has **no runtime dependencies** beyond the bundled `html-to-image`
(optional, for PNG exports). It is pure JavaScript — you can import the
`computeGrade` function directly:

```js
import { computeGrade } from 'features/trust-card/lib/grade.js';

const result = computeGrade({ domain: 'example.com', riskScore: 0.3 });
// result.grade === 'C', result.verdict, result.sections, result.highlights
```

The `renderCard` function draws an HTML `<article>` that can be injected into any
page or snapped to a PNG:

```js
import { renderCard } from 'features/trust-card/lib/card.js';
renderCard(document.getElementById('trust-card'), input);
```

### Share link (data-driven, no server)

Each card can be encoded as a shareable URL fragment:

```js
import { encodeShare, decodeShare } from 'features/trust-card/lib/card.js';
const payload = { domain: 'example.com', riskScore: 0.3, grade: 'B' };
const link = '#' + encodeShare(payload);   // e.g. #dG9...
// Later, on page load:
const data = decodeShare(location.hash.slice(1));  // re-creates the payload
```

## Tests

All 9 unit tests pass (`node --test tests/grade.test.js`). Tests cover:

- The three bundled example JSONs (safe → A, suspicious → C/D, dangerous → F)
- Grade ordering (safe > suspicious > dangerous)
- `gradeFromPoints` boundary thresholds
- Brand-new domain penalty
- Self-signed certificate → F
- Many community reports → F
- Insecure cookies → F
- Missing input defaults to C
- Section weights sum to 1

## License

MIT — see the project root.