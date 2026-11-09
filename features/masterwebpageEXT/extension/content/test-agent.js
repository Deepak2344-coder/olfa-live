/**
 * Tests for features/masterwebpageEXT - verify both scripts load.
 * Run: node --test features/masterwebpageEXT/extension/content/test-agent.js
 */
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const agentPath = path.join(__dirname, 'agent.js');
const schemaPath = path.join(__dirname, 'risk-schema.js');

const agentContent = fs.readFileSync(agentPath, 'utf-8');
const schemaContent = fs.readFileSync(schemaPath, 'utf-8');

test('agent.js contains checkHiddenIframes', () => {
  assert.ok(agentContent.includes('function checkHiddenIframes'));
});

test('agent.js contains checkObfuscatedJS', () => {
  assert.ok(agentContent.includes('function checkObfuscatedJS'));
});

test('agent.js contains checkCookies', () => {
  assert.ok(agentContent.includes('function checkCookies'));
});

test('agent.js contains checkDangerousAPIs', () => {
  assert.ok(agentContent.includes('function checkDangerousAPIs'));
});

test('agent.js contains runDetection', () => {
  assert.ok(agentContent.includes('function runDetection'));
});

test('risk-schema.js contains reason function', () => {
  assert.ok(schemaContent.includes('function reason'));
});

test('risk-schema.js contains makeThreatResult function', () => {
  assert.ok(schemaContent.includes('function makeThreatResult'));
});

test('risk-schema.js exports OlfaSchema', () => {
  assert.ok(schemaContent.includes('OlfaSchema'));
});