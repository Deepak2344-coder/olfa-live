/**
 * Tests for features/page-threat-detector (Node-land).
 * Run: node --test features/page-threat-detector/tests/threat-test.js
 */
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const inspectMod = require('../extension/content/inspect.js');

test('checkHiddenIframes returns empty array in Node', () => {
  const results = inspectMod.checkHiddenIframes();
  assert.ok(Array.isArray(results));
  assert.strictEqual(results.length, 0);
});

test('checkObfuscatedJS detects high entropy', () => {
  const randomish = 'B3h9kP2x/7qLmN5vX1zR4tY6w!@#$%^&*()_+-=';
  const results = inspectMod.checkObfuscatedJS(randomish);
  assert.ok(Array.isArray(results));
});

test('checkDangerousAPIs detects clipboard access', () => {
  const text = 'document.execCommand("copy"); navigator.clipboard.writeText("secret")';
  const results = inspectMod.checkDangerousAPIs(text);
  assert.ok(Array.isArray(results));
  const hasClipboard = results.some(r => r.type === 'clipboard-access');
  assert.ok(hasClipboard, `Expected clipboard-access in ${JSON.stringify(results)}`);
});

test('runDetection runs without throwing', () => {
  const result = inspectMod.runDetection('some script text with eval(function(p,a,c,k,e,d){});');
  assert.ok(Array.isArray(result));
});