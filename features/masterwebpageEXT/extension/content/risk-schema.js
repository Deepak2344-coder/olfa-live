/**
 * Shared risk schema used by masterwebpageEXT content script.
 * Defines the structure for threat and data-sharing findings.
 */

/** Creates a reason object matching the shared contract. */
function reason(code, message, severity, details) {
  return { code, message, severity, details };
}

/** Creates a threat result object. */
function makeThreatResult(url, score, reasons, collected) {
  return {
    url,
    score: Math.round(score * 10000) / 10000,
    level: score >= 0.75 ? 'dangerous' : score >= 0.4 ? 'suspicious' : 'safe',
    reasons,
    collected,
  };
}

/** Shared contract: url, score 0-1, level: safe|suspicious|dangerous, reasons: [] */
const OlfaSchema = {
  reason,
  makeThreatResult,
};

typeof module !== 'undefined' && module.exports
  ? (module.exports = OlfaSchema)
  : (typeof globalThis !== 'undefined' ? globalThis.OlfaSchema : null);