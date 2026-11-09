/**
 * Tests for the trust-card grade rubric.
 * Run: node --test features/trust-card/tests/grade.test.js
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');

const { computeGrade, gradeFromPoints } = require(path.join(__dirname, '..', 'lib', 'grade.js'));

const example = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples', name + '.json'), 'utf8'));

test('the three bundled examples grade A-ish, C/D-ish and F', () => {
  const safe = computeGrade(example('safe'));
  const suspicious = computeGrade(example('suspicious'));
  const dangerous = computeGrade(example('dangerous'));

  assert.strictEqual(safe.grade, 'A');
  assert.ok(['C', 'D'].includes(suspicious.grade), 'suspicious example graded ' + suspicious.grade);
  assert.strictEqual(dangerous.grade, 'F');
});

test('grades are ordered: safe outperforms suspicious outperforms dangerous', () => {
  const a = computeGrade(example('safe')).points;
  const b = computeGrade(example('suspicious')).points;
  const c = computeGrade(example('dangerous')).points;
  assert.ok(a > b, `${a} should beat ${b}`);
  assert.ok(b > c, `${b} should beat ${c}`);
});

test('gradeFromPoints boundaries', () => {
  assert.strictEqual(gradeFromPoints(4), 'A');
  assert.strictEqual(gradeFromPoints(3.5), 'A');
  assert.strictEqual(gradeFromPoints(3.49), 'B');
  assert.strictEqual(gradeFromPoints(2.5), 'B');
  assert.strictEqual(gradeFromPoints(1.5), 'C');
  assert.strictEqual(gradeFromPoints(0.75), 'D');
  assert.strictEqual(gradeFromPoints(0.74), 'F');
});

test('a brand-new domain alone can sink an otherwise fine card', () => {
  const base = { domain: 'new.example', riskScore: 0.1, domainAgeDays: 9000, certificate: { valid: true, daysToExpiry: 100 }, securityHeaders: { grade: 'A' }, cookies: { total: 1, missingSecure: 0, missingHttpOnly: 0 } };
  const old = computeGrade(base);
  const fresh = computeGrade({ ...base, domainAgeDays: 4 });
  assert.ok(fresh.points < old.points);
  assert.strictEqual(fresh.sections.find((s) => s.key === 'age').grade, 'F');
  assert.ok(fresh.highlights.some((h) => h.toLowerCase().includes('brand-new')));
});

test('a self-signed certificate is an automatic F section', () => {
  const result = computeGrade({ domain: 'self.example', riskScore: 0.2, certificate: { selfSigned: true } });
  const cert = result.sections.find((s) => s.key === 'cert');
  assert.strictEqual(cert.grade, 'F');
});

test('many community reports lower the grade', () => {
  const clean = computeGrade({ domain: 'x.example', riskScore: 0.1, reports: { count: 0 } });
  const reported = computeGrade({ domain: 'x.example', riskScore: 0.1, reports: { count: 12 } });
  assert.ok(reported.points < clean.points);
  assert.strictEqual(reported.sections.find((s) => s.key === 'reports').grade, 'F');
});

test('insecure cookies lower the cookie grade', () => {
  const good = computeGrade({ cookies: { total: 4, missingSecure: 0, missingHttpOnly: 0 } });
  const bad = computeGrade({ cookies: { total: 4, missingSecure: 4, missingHttpOnly: 4 } });
  assert.strictEqual(good.sections.find((s) => s.key === 'cookies').grade, 'A');
  assert.strictEqual(bad.sections.find((s) => s.key === 'cookies').grade, 'F');
});

test('missing input never throws and stays at the unknown grade', () => {
  const empty = computeGrade({});
  assert.strictEqual(empty.grade, 'C');
  assert.strictEqual(empty.domain, 'unknown domain');
  assert.strictEqual(empty.sections.length, 6);
  const nothing = computeGrade();
  assert.strictEqual(nothing.grade, 'C');
});

test('every section carries a weight and the weights sum to 1', () => {
  const result = computeGrade(example('safe'));
  const total = result.sections.reduce((sum, s) => sum + s.weight, 0);
  assert.ok(Math.abs(total - 1) < 1e-9, 'weights summed to ' + total);
  for (const section of result.sections) {
    assert.ok(['A', 'B', 'C', 'D', 'F'].includes(section.grade));
    assert.strictEqual(typeof section.detail, 'string');
    assert.ok(section.detail.length > 5);
  }
});
