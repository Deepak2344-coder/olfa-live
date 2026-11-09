/**
 * Unit tests for the page-inspector signal logic.
 * Run: node --test features/page-inspector/tests/signals.test.js
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const { analyze } = require(path.join(__dirname, '..', 'extension', 'lib', 'signals.js'));

const cookie = (over) => ({ name: 'sid', domain: 'shop.example', secure: true, httpOnly: true, sameSite: 'Lax', expires: 0, ...over });
const req = (url, method = 'GET') => ({ url, method, type: 'xmlhttprequest' });

test('a clean first-party page produces no reasons and a safe level', () => {
  const { result, signals } = analyze({
    pageUrl: 'https://shop.example/',
    cookies: [cookie()],
    requests: [req('https://shop.example/app.js')],
    forms: [{ action: 'https://shop.example/login', method: 'post', fields: [{ name: 'password', type: 'password' }] }],
    storageKeys: { local: ['cart'], session: [] },
    fingerprintCalls: [],
  });
  assert.deepStrictEqual(result.reasons, []);
  assert.strictEqual(result.level, 'safe');
  assert.strictEqual(result.score, 0);
  // The only thing worth noting on a clean page is that it keeps a local key.
  assert.deepStrictEqual(signals, { local_storage_keys: 1 });
});

test('insecure and third-party cookies are flagged separately', () => {
  const { signals, result } = analyze({
    pageUrl: 'https://shop.example/',
    cookies: [cookie({ name: 'a', secure: false }), cookie({ name: 'b', domain: '.doubleclick.net' })],
  });
  assert.strictEqual(signals.cookies_missing_secure, 1);
  assert.strictEqual(signals.third_party_cookies, 1);
  assert.strictEqual(signals.known_tracker_cookies, 1);
  const codes = result.reasons.map((r) => r.code);
  assert.ok(codes.includes('cookies_missing_secure'));
  assert.ok(codes.includes('known_tracker'));
});

test('never echoes cookie values - only names and domains leave the collector', () => {
  const { result } = analyze({
    pageUrl: 'https://shop.example/',
    cookies: [{ name: 'sessionid', value: 'SUPER-SECRET-VALUE', domain: 'shop.example', secure: false }],
  });
  assert.ok(!JSON.stringify(result).includes('SUPER-SECRET-VALUE'));
});

test('cross-origin password form is the high-severity case', () => {
  const { result, signals } = analyze({
    pageUrl: 'https://shop.example/',
    forms: [{ action: 'https://collector.example/login', method: 'post', fields: [{ name: 'password', type: 'password' }] }],
  });
  assert.strictEqual(signals.credential_form_cross_origin, true);
  const reason = result.reasons.find((r) => r.code === 'credential_form_cross_origin');
  assert.ok(reason);
  assert.strictEqual(reason.severity, 'high');
  assert.ok(result.level !== 'safe');
});

test('credentials over http are flagged even same-origin', () => {
  const { signals } = analyze({
    pageUrl: 'http://shop.example/',
    forms: [{ action: 'http://shop.example/login', method: 'post', fields: [{ name: 'password', type: 'password' }] }],
  });
  assert.strictEqual(signals.credentials_over_http, true);
});

test('card fields count as secrets too', () => {
  const { signals } = analyze({
    pageUrl: 'https://shop.example/',
    forms: [{ action: 'https://elsewhere.example/pay', method: 'post', fields: [{ name: 'cc-number', autocomplete: 'cc-number' }] }],
  });
  assert.strictEqual(signals.credential_form_cross_origin, true);
});

test('many third parties, cross-origin POSTs and trackers add up', () => {
  const requests = [];
  for (let i = 0; i < 9; i++) requests.push(req(`https://cdn${i}.example.net/x.js`));
  requests.push(req('https://doubleclick.net/pixel.gif'));
  requests.push(req('https://collector.example.net/beacon', 'POST'));
  const { signals, result } = analyze({ pageUrl: 'https://shop.example/', requests });
  assert.strictEqual(signals.many_third_parties, 11); // 9 cdns + doubleclick + collector
  assert.ok(signals.cross_origin_posts >= 1);
  assert.ok(signals.known_trackers >= 1);
  assert.ok(result.score >= 0.4, 'this many signals should reach suspicious');
});

test('fingerprinting raises a medium signal and combines with trackers', () => {
  const { signals, result } = analyze({
    pageUrl: 'https://shop.example/',
    requests: [req('https://doubleclick.net/p.gif')],
    fingerprintCalls: ['canvas', 'audio'],
  });
  assert.strictEqual(signals.fingerprinting, 2);
  const codes = result.reasons.map((r) => r.code);
  assert.ok(codes.includes('fingerprinting'));
  assert.ok(result.score > 0.2);
});

test('every reason satisfies the shared schema', () => {
  const schema = require(path.join(__dirname, '..', 'extension', 'lib', 'risk-schema.js'));
  const { result } = analyze({
    pageUrl: 'http://shop.example/',
    cookies: [cookie({ secure: false, domain: '.doubleclick.net' })],
    requests: [req('https://doubleclick.net/x'), req('https://a.example.net/y', 'POST')],
    forms: [{ action: 'http://evil.example/x', method: 'post', fields: [{ name: 'password', type: 'password' }] }],
    storageKeys: { local: ['uid'], session: [] },
    fingerprintCalls: ['canvas'],
  });
  assert.deepStrictEqual(schema.validateResult(result), []);
  for (const r of result.reasons) assert.ok(/^[a-z0-9_]+$/.test(r.code));
});
