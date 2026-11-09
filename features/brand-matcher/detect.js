const fs = require('fs');
const path = require('path');

// Try to load imagehash; if it fails, we'll use a stub.
let imagehash = null;
try {
  imagehash = require('imagehash');
} catch (e) {
  imagehash = null;
}

/** Return a perceptual hash for an image file.
 *  If imagehash is available, returns a Hash object (with .distance() method).
 *  Otherwise returns a stub hash object where .distance() always returns 64.
 */
function loadImage(filePath) {
  if (!imagehash) {
    // Stub: always report maximally different.
    return { distance: () => 64, toString: () => '00000000', hex: '00000000' };
  }
  // imagehash.fromFile returns a Hash object.
  return imagehash.fromFile(filePath);
}

/** Compare two images by their perceptual hash (Hamming distance).
 *  Lower distance = more similar.
 *  Returns a number 0–64, or 64 if imagehash is not installed.
 */
function compareImages(refPath, testPath) {
  const refHash = loadImage(refPath);
  const testHash = loadImage(testPath);

  // If imagehash is available and the hash objects have .distance(), use it.
  if (imagehash && typeof refHash.distance === 'function') {
    return refHash.distance(testHash);
  }

  // Stub: maximally different.
  return 64;
}

/** Scan a directory for images that resemble the reference.
 *  Returns [{ file, distance }] sorted by distance (closest first).
 */
function scanDirectory(refPath, dirPath) {
  const results = [];
  const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.jpg') || f.endsWith('.png'));

  for (const f of files) {
    const testPath = path.join(dirPath, f);
    try {
      const d = compareImages(refPath, testPath);
      results.push({ file: f, distance: d });
    } catch (err) {
      // skip
    }
  }
  results.sort((a, b) => a.distance - b.distance);
  return results;
}

// CLI entry point.
function runCLI() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error('Usage: node detect.js <reference-image> <test-image>...');
    process.exit(1);
  }
  const ref = args[0];
  for (let i = 1; i < args.length; i++) {
    const testPath = args[i];
    try {
      const d = compareImages(ref, testPath);
      const label = d < 10 ? '(likely imitation)' : '(unrelated)';
      console.log(`  ${testPath}: distance = ${d} ${label}`);
    } catch (err) {
      console.error(`  ${testPath}: ERROR – ${err.message}`);
    }
  }
}

if (require.main === module) {
  runCLI();
}

// Export the public API.
module.exports = { compareImages, loadImage, scanDirectory, runCLI };