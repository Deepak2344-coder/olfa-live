/**
 * Quick smoke test for features/qr-scanner/lib/parse.js
 * Run: node --test features/qr-scanner/tests/qr-test.js
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { scanImage } = require('../lib/parse.js');

test('scanImage runs without throwing', async () => {
  // Create a minimal ImageData
  const pixelData = { data: new Uint8Array(300 * 300 * 4), width: 300, height: 300 };
  const result = await scanImage(pixelData, 300, 300);
  // Shims returns a fake result; just make sure it doesn't crash
  assert.ok(result != null);
});

test('OlfaQR scanImage is a function', () => {
  const { scanImage } = require('../lib/parse.js');
  assert.ok(typeof scanImage === 'function');
});