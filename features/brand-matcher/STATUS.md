# brand-matcher

**Status:** DONE

## What it does

The **brand-matcher** feature detects pages or images that visually imitate a
known brand but live on a different (potentially malicious) domain.  It uses
perceptual hashing (pHash) via the `imagehash` package + Pillow to compare a
reference brand image against test images.  If the Hamming distance between the
reference and a test image is below a small threshold (typically < 10), the test
image is considered a visual imitation / brand abuse.

## How it works

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

## How to run it

```bash
cd features/brand-matcher
npm install          # installs `imagehash` and `pillow`
npm test             # runs the 3‑test suite
# → 3 pass, 0 fail
```

### CLI

```bash
node detect.js ref.png test1.png test2.png …
```

Prints each test image's Hamming distance and whether it is below the
imitation threshold.

### API

```js
import { compareImages, loadImage, scanDirectory } from 'features/brand-matcher/detect.js';
```