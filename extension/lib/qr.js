// Link and QR helpers: which targets are worth checking, and how to mark them.
//
// Ported from features/qr-link-detector/extension/content/detect.js. Pure and
// ES-module — no chrome.*, no DOM required, so `node --test` covers it.
//
// The content script collects raw hrefs and decodes QR images with the vendored
// jsQR; this module decides what counts as a checkable target.

/** Hard caps so one huge page cannot flood the API. */
export const MAX_LINKS = 100;
export const MAX_QR_IMAGES = 24;
export const MIN_QR_SIZE = 48;
export const QR_MAX_ASPECT = 1.35;

/** Classes the content script adds (see content/style.css). */
export const UNSAFE_CLASS = "olfa-unsafe";
export const SUSPICIOUS_CLASS = "olfa-suspicious";

/** hrefs that are not web links and must never be sent anywhere. */
const SKIP_SCHEME = /^\s*(#|mailto:|tel:|sms:|javascript:|data:|blob:|about:|chrome:|file:|ftp:)/i;
const URL_IN_TEXT = /https?:\/\/[^\s"'<>()]+/i;

/**
 * Turn a raw href or scanned text into an absolute http(s) URL, or null.
 * Fragments are stripped because they never leave the browser.
 * @param {string} raw
 * @param {string} [base]
 * @returns {string|null}
 */
export function toHttpUrl(raw, base) {
  if (typeof raw !== "string") return null;
  const value = raw.trim();
  if (!value || SKIP_SCHEME.test(value)) return null;

  let url;
  try {
    url = base ? new URL(value, base) : new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  url.hash = "";
  return url.href;
}

/**
 * Unique http(s) links from a list of hrefs, order preserved.
 * @param {string[]} hrefs
 * @param {string} [base]
 * @param {number} [limit]
 * @returns {string[]}
 */
export function collectLinkUrls(hrefs, base, limit = MAX_LINKS) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(hrefs) ? hrefs : []) {
    if (out.length >= limit) break;
    const url = toHttpUrl(raw, base);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push(url);
  }
  return out;
}

/**
 * Is this image/canvas size worth handing to the QR decoder?
 * @param {number} width
 * @param {number} height
 * @returns {boolean}
 */
export function isQrCandidate(width, height) {
  const w = Number(width);
  const h = Number(height);
  if (!Number.isFinite(w) || !Number.isFinite(h)) return false;
  if (w < MIN_QR_SIZE || h < MIN_QR_SIZE) return false;
  const ratio = w / h;
  return ratio <= QR_MAX_ASPECT && ratio >= 1 / QR_MAX_ASPECT;
}

/**
 * The URL a QR payload points at, or null for plain text (WiFi, vCard, coupon).
 * @param {string} text
 * @returns {string|null}
 */
export function qrTextToUrl(text) {
  const value = String(text || "").trim();
  if (!value) return null;

  const direct = toHttpUrl(value);
  if (direct) return direct;

  if (/^www\./i.test(value)) return toHttpUrl(`https://${value}`);

  const embedded = value.match(URL_IN_TEXT);
  if (embedded) return toHttpUrl(embedded[0]);

  return null;
}

/**
 * CSS class for a verdict: dangerous red, suspicious amber, safe untouched.
 * @param {{risk?: number, verdict?: string}|null} result internal-shape result
 * @returns {string|null}
 */
export function highlightClass(result) {
  if (!result) return null;
  const verdict = result.verdict;
  const risk = Number(result.risk);
  if (verdict === "dangerous" || (Number.isFinite(risk) && risk >= 0.75)) return UNSAFE_CLASS;
  if (verdict === "suspicious" || (Number.isFinite(risk) && risk >= 0.4)) return SUSPICIOUS_CLASS;
  return null;
}

/**
 * First human-readable reason, for a tooltip.
 * @param {{reasons?: Array}|null} result
 * @returns {string}
 */
export function reasonText(result) {
  if (!result || !Array.isArray(result.reasons)) return "";
  const first = result.reasons.find((r) => r && typeof r.text === "string" && r.text.trim());
  return first ? String(first.text) : "";
}

/**
 * Split link results into counts for the popup.
 * @param {Record<string, {verdict?: string}>} verdicts url -> result
 * @returns {{checked: number, safe: number, suspicious: number, dangerous: number, flagged: string[]}}
 */
export function summarizeLinks(verdicts) {
  const entries = Object.entries(verdicts || {});
  const summary = { checked: entries.length, safe: 0, suspicious: 0, dangerous: 0, flagged: [] };
  for (const [url, result] of entries) {
    const verdict = result && result.verdict;
    if (verdict === "dangerous") {
      summary.dangerous += 1;
      summary.flagged.push(url);
    } else if (verdict === "suspicious") {
      summary.suspicious += 1;
      summary.flagged.push(url);
    } else {
      summary.safe += 1;
    }
  }
  summary.flagged = summary.flagged.slice(0, 10);
  return summary;
}
