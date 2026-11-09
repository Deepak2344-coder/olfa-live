/**
 * Tests for features/multilingual-alerts/lib/alerts.js
 * Run: node --test features/multilingual-alerts/tests/alerts.test.js
 */
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { getAlert, listReasons, validateReason } = require('../lib/alerts.js');

test('getAlert returns English warning for PHISH_URL', () => {
  const result = getAlert('PHISH_URL', 'en');
  assert.strictEqual(result, 'Warning: This page impersonates a login screen.');
});

test('getAlert returns Hindi warning for TYPOSQUAT', () => {
  const result = getAlert('TYPOSQUAT', 'hi');
  assert.strictEqual(result, 'चेतावनी: डोमेन एक प्रसिद्ध ब्रांड जैसा दिखता है।');
});

test('getAlert returns Bengali warning for INVALID_CERT', () => {
  const result = getAlert('INVALID_CERT', 'bn');
  assert.strictEqual(result, 'সতর্কতা: সাইটের সার্টিফিকেট বৈধ নেই বা সমাপ্ত হয়েছে।');
});

test('getAlert falls back to English for unknown language', () => {
  const result = getAlert('PHISH_URL', 'fr'); // unsupported
  assert.strictEqual(result, 'Warning: This page impersonates a login screen.');
});

test('getAlert returns default for unknown reason code', () => {
  const result = getAlert('NONEXISTENT', 'en');
  assert.strictEqual(result, 'Warning: unknown risk.');
});

test('listReasons returns all EN codes', () => {
  const codes = listReasons('en');
  assert.ok(codes.includes('PHISH_URL'));
  assert.ok(codes.includes('TYPOSQUAT'));
  assert.ok(codes.includes('URGENT_POPUP'));
  assert.ok(codes.includes('INVALID_CERT'));
  assert.ok(codes.includes('COOKIE_TRACK'));
  assert.strictEqual(codes.length, 5);
});

test('listReasons works for HI and BN', () => {
  assert.strictEqual(listReasons('hi').length, 5);
  assert.strictEqual(listReasons('bn').length, 5);
});

test('validateReason checks EN codes', () => {
  assert.ok(validateReason('PHISH_URL', 'en'));
  assert.ok(validateReason('TYPOSQUAT', 'en'));
  assert.ok(!validateReason('NONEXISTENT', 'en'));
});

test('validateReason checks HI codes', () => {
  assert.ok(validateReason('PHISH_URL', 'hi'));
  assert.ok(validateReason('TYPOSQUAT', 'hi'));
});

test('validateReason checks BN codes', () => {
  assert.ok(validateReason('PHISH_URL', 'bn'));
  assert.ok(validateReason('TYPOSQUAT', 'bn'));
});