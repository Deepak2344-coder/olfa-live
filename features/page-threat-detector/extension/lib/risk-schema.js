/**
 * Olfa shared risk-score helpers (JavaScript).
 *
 * One file, three consumers:
 *   - MV3 service worker:  importScripts('../shared/risk-schema.js'); OlfaSchema.makeResult(...)
 *   - web page / content script: <script src="../shared/risk-schema.js"></script>
 *   - Node tests:          const OlfaSchema = require('../../shared/risk-schema.js')
 *
 * Keep this file dependency-free; it is copied into every feature by path reference.
 */
(function (root) {
  'use strict';

  /** Risk buckets. Keep in sync with features/shared/README.md. */
  const THRESHOLDS = { suspicious: 0.4, dangerous: 0.75 };
  const LEVELS = ['safe', 'suspicious', 'dangerous'];
  const SEVERITIES = ['low', 'medium', 'high'];

  /** Clamp anything into [0, 1]; non-numbers become 0. */
  function clampScore(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return 0;
    return Math.min(1, Math.max(0, n));
  }

  /** score -> 'safe' | 'suspicious' | 'dangerous' */
  function levelFromScore(score) {
    const s = clampScore(score);
    if (s >= THRESHOLDS.dangerous) return 'dangerous';
    if (s >= THRESHOLDS.suspicious) return 'suspicious';
    return 'safe';
  }

  /** Build one entry for the `reasons` array. */
  function reason(code, message, severity, details) {
    return {
      code: String(code),
      message: String(message),
      severity: SEVERITIES.indexOf(severity) === -1 ? 'medium' : severity,
      ...(details ? { details: details } : {}),
    };
  }

  /** Build a complete risk result in the shared schema. */
  function makeResult(url, score, reasons, extra) {
    const s = Math.round(clampScore(score) * 10000) / 10000;
    return {
      url: String(url || ''),
      score: s,
      level: levelFromScore(s),
      reasons: Array.isArray(reasons) ? reasons : [],
      ...(extra || {}),
    };
  }

  /** Cheap structural validation. Returns an array of problems (empty = valid). */
  function validateResult(obj) {
    const problems = [];
    if (!obj || typeof obj !== 'object') return ['result is not an object'];
    if (typeof obj.url !== 'string') problems.push('url must be a string');
    if (typeof obj.score !== 'number' || obj.score < 0 || obj.score > 1) {
      problems.push('score must be a number between 0 and 1');
    }
    if (LEVELS.indexOf(obj.level) === -1) problems.push('level must be safe|suspicious|dangerous');
    if (!Array.isArray(obj.reasons)) problems.push('reasons must be an array');
    else {
      obj.reasons.forEach(function (r, i) {
        if (!r || typeof r.code !== 'string' || typeof r.message !== 'string') {
          problems.push('reasons[' + i + '] needs string code and message');
        }
      });
    }
    return problems;
  }

  const api = { THRESHOLDS, LEVELS, SEVERITIES, clampScore, levelFromScore, reason, makeResult, validateResult };

  root.OlfaSchema = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
