/**
 * Tests for features/qr-link-detector detection logic.
 * Run: node --test features/qr-link-detector/tests/detect-test.js
 */
'use strict';
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('assert');

const agentPath = path.join(__dirname, '..', 'extension', 'content', 'agent.js');
const manifestPath = path.join(__dirname, '..', 'extension', 'manifest.json');

test('agent.js file exists and is readable', () => {
  const stat = fs.statSync(agentPath);
  assert.ok(stat.isFile());
});

test('manifest.json file exists and is readable', () => {
  const stat = fs.statSync(manifestPath);
  assert.ok(stat.isFile());
});

test('agent.js contains "scanPageForQR" string', () => {
  const content = fs.readFileSync(agentPath, 'utf-8');
  assert.ok(content.includes('scanPageForQR'));
});

test('manifest.json contains "content_scripts"', () => {
  const content = fs.readFileSync(manifestPath, 'utf-8');
  assert.ok(content.includes('content_scripts'));
});

test('manifest.json is valid JSON', () => {
  const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  assert.ok(parsed.name);
  assert.ok(parsed.version);
});