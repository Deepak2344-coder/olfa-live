'use strict';
/**
 * Unit tests for the realtime-blocking decision logic.
 * Run: node --test features/realtime-blocking/tests
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const tier = require(path.join(__dirname, '..', 'extension', 'lib', 'tier.js'));
const schema = require(path.join(__dirname, '..', 'extension', 'lib', 'risk-schema.js'));

test('decideTier: three tiers and the whitelist override', () => {
  assert.strictEqual(tier.decideTier(0.95), 'block');
  assert.strictEqual(tier.decideTier(0.91), 'block');
  assert.strictEqual(tier.decideTier(0.9), 'warn');
  assert.strictEqual(tier.decideTier(0.4), 'warn');
  assert.strictEqual(tier.decideTier(0.39), 'log');
  assert.strictEqual(tier.decideTier(0.0), 'log');
  // A whitelisted host always wins, even at score 1.
  assert.strictEqual(tier.decideTier(1, { whitelisted: true }), 'allow');
  // Blocklist flag forces block even with a low score.
  assert.strictEqual(tier.decideTier(0.1, { blocklisted: true }), 'block');
});

test('whitelist covers top domains, .gov.in and .edu', () => {
  assert.ok(tier.isWhitelisted('google.com'));
  assert.ok(tier.isWhitelisted('mail.google.com'));
  assert.ok(tier.isWhitelisted('india.gov.in'));
  assert.ok(tier.isWhitelisted('iitb.ac.in'));
  assert.ok(tier.isWhitelisted('mit.edu'));
  assert.ok(tier.isWhitelisted('en.wikipedia.org'));
  assert.ok(!tier.isWhitelisted('google.com.evil.example'));
  assert.ok(!tier.isWhitelisted('paypa1-login.example'));
});

test('blocklist matches the host and its subdomains', () => {
  assert.ok(tier.isBlocklisted('paypa1-login.example'));
  assert.ok(tier.isBlocklisted('www.paypa1-login.example'));
  assert.ok(!tier.isBlocklisted('example.com'));
});

test('typosquat detects lookalike domains but not the real ones', () => {
  const paypal = tier.typosquat('paypa1.com');
  assert.ok(paypal, 'paypa1.com should look like paypal');
  assert.strictEqual(paypal.brand, 'paypal');
  assert.strictEqual(paypal.official, false);

  assert.strictEqual(tier.typosquat('paypal.com'), null, 'the real domain must not be flagged');
  assert.strictEqual(tier.typosquat('www.paypal.com'), null);
  assert.strictEqual(tier.typosquat('google.co.in'), null);

  const sub = tier.typosquat('paypal.login-secure.xyz');
  assert.ok(sub, 'brand used as a subdomain label should be caught');
  assert.strictEqual(sub.brand, 'paypal');
});

test('levenshtein basic sanity', () => {
  assert.strictEqual(tier.levenshtein('paypal', 'paypal'), 0);
  assert.strictEqual(tier.levenshtein('paypa1', 'paypal'), 1);
  assert.strictEqual(tier.levenshtein('kitten', 'sitting'), 3);
});

test('heuristics flag http, IP hosts, punycode and lure keywords', () => {
  const codes = (url) => tier.heuristics(url).map((r) => r.code);
  assert.ok(codes('http://example.com/').includes('insecure_http'));
  assert.ok(codes('http://185.199.108.153/login').includes('ip_literal_host'));
  assert.ok(codes('https://xn--pypal-4ve.com/').includes('punycode_host'));
  assert.ok(codes('https://a.b.c.d.example.com/').includes('many_subdomains'));
  assert.ok(codes('https://bank-kyc-verify-update.xyz/login').includes('lure_keywords'));
  // A clean https URL on a plain domain produces no high-severity signal.
  const clean = tier.heuristics('https://example.org/docs/page');
  assert.ok(!clean.some((r) => r.severity === 'high'), 'clean URL should not raise a high signal');
});

test('localCheck: high-risk URL reaches the block tier', () => {
  const { result, tier: t } = tier.localCheck('http://paypa1-login.example/verify?account=1');
  assert.strictEqual(t, 'block');
  assert.strictEqual(result.level, 'dangerous');
  assert.ok(result.score > 0.9);
  assert.deepStrictEqual(schema.validateResult(result), []);
  const codes = result.reasons.map((r) => r.code);
  assert.ok(codes.includes('blocklisted'));
});

test('localCheck: whitelisted page never blocks', () => {
  const { tier: t, result } = tier.localCheck('https://india.gov.in/scheme/list');
  assert.strictEqual(t, 'allow');
  assert.strictEqual(result.level, 'safe');
});

test('localCheck: clean site lands in the silent log tier', () => {
  const { tier: t } = tier.localCheck('https://example.org/');
  assert.strictEqual(t, 'log');
});

test('localCheck: medium-risk lookalike lands in the warn tier', () => {
  // typosquat (high) + one medium heuristic, without a blocklist hit
  const { tier: t } = tier.localCheck('https://paypa1.com/');
  assert.strictEqual(t, 'warn');
});

test('reason objects always satisfy the shared schema', () => {
  const reasons = tier.heuristics('http://user:pass@10.0.0.1/x');
  for (const r of reasons) {
    assert.strictEqual(typeof r.code, 'string');
    assert.ok(/^[a-z0-9_]+$/.test(r.code), `${r.code} must be snake_case`);
    assert.strictEqual(typeof r.message, 'string');
  }
});
