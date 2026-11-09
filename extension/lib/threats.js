// In-page threat detection: clickjacking, obfuscated scripts and API abuse.
//
// Ported from features/page-threat-detector (content/inspect.js) but with the
// DOM facts collected by the content script and passed in as plain data, so the
// judgement stays pure and unit-testable in Node.
import { clampRisk, reason, verdictFromRisk } from "./normalize.js";

/** Character-uniqueness ratio above which inline script text looks packed. */
export const OBFUSCATION_RATIO = 0.75;
/** Scripts shorter than this are never judged on entropy. */
export const MIN_SCRIPT_LENGTH = 200;

const PACKER_PATTERN = /eval\s*\(|new\s+Function\s*\(|fromCharCode|arguments\.callee/;
const CLIPBOARD_PATTERN = /execCommand|clipboard\.write|navigator\.clipboard/;
const KEYSTROKE_PATTERN = /keydown|keypress|keyup|onkeydown|onkeyup/;

/**
 * Ratio of unique characters to total characters.
 * @param {string} text
 * @returns {number}
 */
export function entropyRatio(text) {
  const value = String(text || "");
  if (!value.length) return 0;
  return new Set(value).size / value.length;
}

/**
 * Judge one inline script body.
 * @param {string} text
 * @returns {boolean} true when it looks packed/obfuscated
 */
export function looksObfuscated(text) {
  const value = String(text || "");
  if (value.length < MIN_SCRIPT_LENGTH) return false;
  return entropyRatio(value) > OBFUSCATION_RATIO || PACKER_PATTERN.test(value);
}

/**
 * Judge collected page facts.
 *
 * @param {object} facts
 *   {hiddenIframes: [{src, width, height}], overlays: [{tag, description}],
 *    scripts: string[], apiCalls: string[]}
 *   `apiCalls` holds the names the fingerprint/content hooks recorded, e.g.
 *   "clipboard.read", "clipboard.write", "permissions.query".
 * @returns {{risk: number, verdict: string, score: number, reasons: Array, threats: Array}}
 */
export function scanThreats(facts) {
  const input = facts && typeof facts === "object" ? facts : {};
  const hiddenIframes = Array.isArray(input.hiddenIframes) ? input.hiddenIframes.filter(Boolean) : [];
  const overlays = Array.isArray(input.overlays) ? input.overlays.filter(Boolean) : [];
  const scripts = Array.isArray(input.scripts) ? input.scripts.filter((s) => typeof s === "string") : [];
  const apiCalls = Array.isArray(input.apiCalls) ? input.apiCalls.filter(Boolean).map(String) : [];

  const reasons = [];
  const threats = [];

  if (hiddenIframes.length) {
    const first = hiddenIframes[0];
    reasons.push(
      reason("hidden_iframe", `${hiddenIframes.length} iframe(s) are invisible or zero-sized, a common clickjacking setup.`, "medium", {
        src: first && first.src ? String(first.src).slice(0, 200) : "",
      })
    );
    threats.push({ type: "hidden_iframe", count: hiddenIframes.length });
  }

  if (overlays.length) {
    const top = overlays[0] || {};
    reasons.push(
      reason("clickjacking_overlay", "A transparent overlay covers most of the page and can steal clicks meant for the page underneath.", "high", {
        tag: top.tag || "",
        description: top.description || "",
      })
    );
    threats.push({ type: "clickjacking_overlay", count: overlays.length });
  }

  const obfuscated = scripts.filter(looksObfuscated);
  if (obfuscated.length) {
    reasons.push(
      reason("obfuscated_script", `${obfuscated.length} inline script(s) are packed or obfuscated, which hides what they do.`, "medium")
    );
    threats.push({ type: "obfuscated_script", count: obfuscated.length });
  }

  const clipboard = apiCalls.filter((call) => CLIPBOARD_PATTERN.test(call) || call.startsWith("clipboard"));
  if (clipboard.length) {
    reasons.push(reason("clipboard_hijack", `The page touches the clipboard API (${Array.from(new Set(clipboard)).join(", ")}).`, "medium"));
    threats.push({ type: "clipboard_hijack", count: clipboard.length });
  }

  const keystroke = apiCalls.filter((call) => KEYSTROKE_PATTERN.test(call));
  if (keystroke.length && apiCalls.some((call) => call === "clipboard.write" || call === "canvas.toDataURL")) {
    reasons.push(
      reason("keystroke_exfiltration", "Key events and a data-copying API are used together, which is how typed secrets get lifted.", "high")
    );
    threats.push({ type: "keystroke_exfiltration", count: keystroke.length });
  }

  const permissions = apiCalls.filter((call) => call.startsWith("permissions."));
  if (permissions.length) {
    reasons.push(reason("risky_permission_request", "The page asks the browser for extra permissions such as notifications or location.", "low"));
    threats.push({ type: "risky_permission_request", count: permissions.length });
  }

  const risk = clampRisk(reasons.reduce((sum, item) => sum + (item.severity === "high" ? 0.42 : item.severity === "medium" ? 0.2 : 0.06), 0));

  return {
    risk,
    verdict: verdictFromRisk(risk),
    score: Math.round((1 - risk) * 100),
    reasons,
    threats,
  };
}
