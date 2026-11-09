// Pure logic for the extension. No chrome.* APIs here, so it can be tested
// with plain `node --test`.

export const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const REPORT_CATEGORIES = ["phishing", "scam", "impersonation", "legitimate"];

/**
 * True only for http(s) URLs — the only pages we ever scan.
 * @param {string} url
 * @returns {boolean}
 */
export function isHttpUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Cache freshness check.
 * @param {number} ts timestamp when the entry was stored
 * @param {number} now current time
 * @param {number} [ttlMs]
 * @returns {boolean}
 */
export function isCacheFresh(ts, now, ttlMs = CACHE_TTL_MS) {
  const t = Number(ts);
  if (!Number.isFinite(t) || t > now) return false; // missing or from the future
  return now - t < ttlMs;
}

/**
 * Badge color + short text for a scan state.
 * @param {{kind: "scanning"|"error"|"off"} | {kind: "done", verdict: string, score: number}} state
 * @returns {{color: string, text: string, tooltip: string}}
 */
export function badgeFor(state) {
  const GRAY = "#64748b";
  switch (state?.kind) {
    case "scanning":
      return { color: GRAY, text: "…", tooltip: "Olfa: scanning…" };
    case "error":
      return { color: GRAY, text: "×", tooltip: "Olfa: scan failed" };
    case "off":
      return { color: GRAY, text: "", tooltip: "Olfa: off (enable in options)" };
    default: {
      const verdict = state.verdict || "";
      const score = Number(state.score);
      if (verdict === "safe") {
        return { color: "#16a34a", text: "OK", tooltip: "Olfa: safe (score " + Math.round(score) + ")" };
      }
      if (verdict === "suspicious") {
        return { color: "#d97706", text: "!", tooltip: "Olfa: suspicious (score " + Math.round(score) + ")" };
      }
      if (verdict === "dangerous") {
        return { color: "#dc2626", text: "!!", tooltip: "Olfa: dangerous (score " + Math.round(score) + ")" };
      }
      return { color: GRAY, text: "×", tooltip: "Olfa: unknown result" };
    }
  }
}

/**
 * The first `n` reasons, strongest first. Falls back to flattening engine
 * reasons when the top-level list is missing.
 * @param {object} result analyze response
 * @param {number} [n=3]
 * @returns {Array<{engine?: string, severity: string, text: string}>}
 */
export function topReasons(result, n = 3) {
  const list = Array.isArray(result?.reasons) && result.reasons.length > 0
    ? result.reasons
    : (result?.engines || []).flatMap((e) => (e.reasons || []).map((r) => ({ engine: e.name, severity: r.severity, text: r.text })));
  return list.slice(0, n).filter((r) => r && typeof r.text === "string");
}

/**
 * Cap the size of the URL cache.
 * @param {Record<string, {ts: number, result: object}>} cache
 * @param {number} [max=100]
 * @returns {Record<string, {ts: number, result: object}>} pruned copy, oldest first out
 */
export function pruneCache(cache, max = 100) {
  const entries = Object.entries(cache || {}).sort((a, b) => a[1].ts - b[1].ts);
  const kept = entries.slice(-max);
  return Object.fromEntries(kept);
}

/**
 * Small async delay helper.
 * @param {number} ms
 * @returns {Promise<void>}
 */
export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Run `fn` over `items` with at most `limit` in flight. Results keep input
 * order; failures resolve to null instead of rejecting, so one bad URL cannot
 * abort a page scan.
 *
 * @template T, R
 * @param {T[]} items
 * @param {number} limit
 * @param {(item: T, index: number) => Promise<R>} fn
 * @returns {Promise<Array<R|null>>}
 */
export async function mapLimit(items, limit, fn) {
  const list = Array.isArray(items) ? items : [];
  const cap = Math.max(1, Number(limit) || 1);
  const results = new Array(list.length).fill(null);
  let next = 0;

  async function worker() {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= list.length) return;
      try {
        results[index] = await fn(list[index], index);
      } catch {
        results[index] = null;
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(cap, list.length) }, worker));
  return results;
}
