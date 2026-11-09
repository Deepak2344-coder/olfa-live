/**
 * Olfa QR-schema — extend the shared risk-schema with QR‑specific fields.
 *
 * The shared schema (features/shared/risk-schema.json) defines:
 *   { url: string, score: 0-1, level: "safe"|"suspicious"|"dangerous", reasons: [] }
 *
 * This module adds QR‑code–specific metadata so the rest of Olfa can
 * classify a QR‑encoded link without re‑inventing the wheel.
 */

// Shared contract – keep in sync with features/shared/risk-schema.js
const QR_SCORE_THRESHOLDS = {
  safe: 0.4,     // score < 0.4  → safe
  suspicious: 0.75,  // 0.4 ≤ score < 0.75 → suspicious
  dangerous: 1,    // score ≥ 0.75 → dangerous
};

// QR‑specific result shape (JavaScript type, not a JSON file – used by
// documentation and runtime checks).
function qrResult(url, score, level, reasons, qrText, qrFormat) {
  this.url = url;
  this.score = Number(score);
  this.level = level;        // 'safe' | 'suspicious' | 'dangerous'
  this.reasons = reasons || [];   // human‑readable reasons
  this.qrText = qrText || '';     // the text the QR encoded
  this.qrFormat = qrFormat || 'UNKNOWN'; // e.g. "URL_VCARD"
  this.timestamp = Date.now();
}

// Convert a numeric Olfa score (0–1) into a level string.
function levelFromScore(score) {
  const s = Number(score);
  if (s < QR_SCORE_THRESHOLDS.safe) return 'safe';
  if (s < QR_SCORE_THRESHOLDS.suspicious) return 'suspicious';
  return 'dangerous';
}

// Validate a QR result against the shared schema + QR extras.
function validateQrResult(obj) {
  if (typeof obj !== 'object' || obj === null) return { valid: false, error: 'not an object' };

  const url = obj.url;
  const score = obj.score;
  const level = obj.level;
  const reasons = obj.reasons;
  const qrText = obj.qrText;
  const qrFormat = obj.qrFormat;

  if (typeof url !== 'string' || url.length === 0) {
    return { valid: false, error: 'missing or invalid url' };
  }
  if (typeof score !== 'number' || Number.isNaN(score) || score < 0 || score > 1) {
    return { valid: false, error: 'score must be a number in [0,1]' };
  }
  if (typeof level !== 'string' || !['safe', 'suspicious', 'dangerous'].includes(level)) {
    // derive level from score if not supplied
    obj.level = levelFromScore(score);
  }
  if (!Array.isArray(reasons)) {
    return { valid: false, error: 'reasons must be an array' };
  }
  if (typeof qrText !== 'string') {
    return { valid: false, error: 'qrText must be a string' };
  }
  if (typeof qrFormat !== 'string') {
    return { valid: false, error: 'qrFormat must be a string' };
  }

  return { valid: true, result: new qrResult(obj.url, obj.score, obj.level, obj.reasons, obj.qrText, obj.qrFormat) };
}

// Export the helpers (CJS for compatibility with the shared schema module).
module.exports = {
  qrResult,
  levelFromScore,
  validateQrResult,
  QR_SCORE_THRESHOLDS,
};

// Also expose on globalThis for browser usage (the shared schema does the same).
if (typeof globalThis !== 'undefined') {
  globalThis.OlfaQrSchema = {
    qrResult,
    levelFromScore,
    validateQrResult,
    QR_SCORE_THRESHOLDS,
  };
}