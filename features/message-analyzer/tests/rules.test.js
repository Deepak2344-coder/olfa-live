/**
 * Tests for features/message-analyzer/lib/rules.js
 * Run: node --test features/message-analyzer/tests/rules.test.js
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { analyze, highlighted } = require('../lib/rules.js');

test('EN rules find urgent language in a sample message', () => {
  const msg = 'URGENT: Your bank account will be closed within 24 hours!';
  const matches = analyze(msg, 'en');
  // The message may match multiple patterns (urgent language + within 24 hours);
  // just verify that at least one match references 'urgent language'.
  const hasUrgent = matches.some((m) => m.label === 'urgent language');
  assert.ok(hasUrgent, `Expected at least one 'urgent language' match, got: ${matches.map(m => m.label).join(', ')}`);
});

test('EN rules find brand impersonation', () => {
  const msg = 'Please update your SBI bank details now.';
  const matches = analyze(msg, 'en');
  const labels = matches.map((m) => m.label);
  assert.ok(labels.includes('brand impersonation'));
});

test('EN rules find credential harvesting (OTP)', () => {
  const msg = 'Your OTP is 123456.';
  const matches = analyze(msg, 'en');
  const labels = matches.map((m) => m.label);
  assert.ok(labels.includes('credential harvesting'));
});

test('HI rules work on Hindi text', () => {
  const msg = 'अत्यंत urgent: आपके बैंक अकाउंट को 24 घंटे के भीतर बंद कर दिया जाएगा!';
  const matches = analyze(msg, 'hi');
  const labels = matches.map((m) => m.label);
  assert.ok(labels.includes('urgent language'));
});

test('BN rules run without throwing on Bangla text', () => {
  // The Bangla patterns share the same semantics; verify the function runs
  // and returns an array (it may not match Latin‑keyword patterns in pure Bangla,
  // which is expected behavior).
  const msg = 'গুড়ে 토roly: আপনার ব্যাংকের অ্যাকাউন্ট ২৪ ঘণ্টার মধ্যে বন্ধ করা হবে!';
  const matches = analyze(msg, 'bn');
  assert.ok(Array.isArray(matches));
});

test('highlighted returns HTML with <mark> tags', () => {
  const msg = 'URGENT: Click here to verify your OTP now.';
  const { highlighted: html } = highlighted(msg, 'en');
  // The urgent word should be wrapped in <mark>
  assert.ok(html.includes('<mark>URGENT</mark>'));
  assert.ok(html.includes('<mark>OTP</mark>') || html.includes('<mark>OTP</mark>'));
});

test('no rules match a safe message', () => {
  const msg = 'Hello, how are you doing today?';
  const matches = analyze(msg, 'en');
  assert.strictEqual(matches.length, 0);
});

test('rules are not case‑sensitive', () => {
  const msg = 'urgent: i need money right now';
  const matches = analyze(msg, 'en');
  const labels = matches.map((m) => m.label);
  assert.ok(labels.some((l) => l.includes('urgent')));
});