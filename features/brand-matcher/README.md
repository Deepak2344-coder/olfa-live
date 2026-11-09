# brand-matcher

**Status:** DONE

## What it does

The **brand-matcher** feature detects pages or images that visually imitate a
known brand but live on a different (potentially malicious) domain.  It uses
perceptual hashing (pHash) via the `imagehash` package + Pillow to compare a
reference brand image against test images.  If the Hamming distance between the
reference and a test image is below a small threshold (typically < 10), the test
image is considered a visual imitation / brand abuse.

### How it works

1. **Reference image** – the official brand logo/wordmark (e.g. the Olfa
   wordmark).  This is a single PNG file that the user provides or that is
   bundled with the feature.
2. **Test images** – any PNG/JPEG files scanned from a directory or passed
   as paths.
3. **pHash comparison** – both the reference and test images are converted to
   a 64‑bit perceptual hash.  The `hash.distance()` method returns the Hamming
   distance (0 = identical, 64 = completely different).
4. **Threshold** – distances < 10 indicate the images are visually very
   similar; distances ≥ 10 indicate they are unrelated.

### API

```js
import { compareImages, loadImage, scanDirectory } from 'features/brand-matcher/detect.js';

// Compare two specific images:
const distance = await compareImages('ref.png', 'test.png');
// distance is an integer 0–64 (Hamming distance)

// Scan a whole directory for imitations:
const results = scanDirectory('ref.png', 'images/');
// results = [{ file: 'img1.png', distance: 5 }, { file: 'img2.png', distance: 12 }, ...]
// Sorted by distance (closest first).
```

### CLI

```bash
node features/brand-matcher/detect.js ref.png test1.png test2.png ...
```

Prints each test image's Hamming distance and whether it is below the
imitation threshold (default < 10).

## Installation

```bash
cd features/brand-matcher
npm install   # installs `imagehash` and `pillow` (see requirements.txt)
```

## Tests

```bash
npm test
# 3 tests verify:
#   - compareImages returns a number in [0, 64]
#   - loadImage can read a PNG and produce a hash with a distance method
#   - compareImages produces a lower distance for a mimicking image than for
#     an unrelated safe image (both distances are valid numbers)
```

## License

MIT — see the project root.