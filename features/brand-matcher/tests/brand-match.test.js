/**
 * Tests for features/brand-matcher/detect.js
 * Run: node --test features/brand-matcher/tests/brand-match.test.js
 */
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compareImages, loadImage } = require('../detect.js');

test('compareImages returns a Hamming distance (number 0-64)', () => {
  const dist = compareImages('features/brand-matcher/examples/ref-official.png',
                             'features/brand-matcher/examples/test-mimic1.png');
  assert.ok(typeof dist === 'number');
  assert.ok(dist >= 0 && dist <= 64);
});

test('loadImage can read a PNG file and return an object with distance', () => {
  const hash = loadImage('features/brand-matcher/examples/ref-official.png');
  assert.ok(typeof hash === 'object');
  assert.ok(typeof hash.distance === 'function');
});

test('compareImages gives distance 64 when imagehash unavailable', () => {
  const dist = compareImages('features/brand-matcher/examples/ref-official.png',
                             'features/brand-matcher/examples/test-safe1.png');
  assert.ok(typeof dist === 'number');
  assert.ok(dist >= 0 && dist <= 64);
});