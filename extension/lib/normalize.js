// Schema bridge.
//
// This repo speaks two risk vocabularies and they must not leak into the UI:
//
//   POST /analyze  ->  {score: 0-100, verdict, engines[], reasons[{engine,severity,text}]}
//                      (backend/app.py, /shared/contracts)
//
//   POST /scan     ->  {score: 0-1, level, reasons[{code,severity,message}]}
//                      (features/shared/schema.json)
//
// Everything inside the extension uses ONE shape:
//
//   {url, risk, verdict, score, reasons: [{code, severity, text, engine?}]}
//
// `risk` is 0-1 where higher = riskier; `score` is the 0-100 trust score the
// existing UI already shows. Pure module: no chrome.* and no network.

/** risk below this is safe, at or above SUSPICIOUS_MIN is suspicious */
export const RISK_SAFE_MAX = 0.4;
/** risk at or above this is dangerous */
export const RISK_DANGEROUS_MIN = 0.75;

export const VERDICTS = ["safe", "suspicious", "dangerous"];
export const SEVERITIES = ["low", "medium", "high"];

/**
 * Clamp a number into [0, 1]; NaN and non-numbers become 0.
 * @param {unknown} value
 * @returns {number}
 */
export function clampRisk(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.min(1, Math.max(0, Math.round(n * 10000) / 10000));
}

/**
 * Map a 0-1 risk to the shared verdict vocabulary.
 * @param {number} risk
 * @returns {"safe"|"suspicious"|"dangerous"}
 */
export function verdictFromRisk(risk) {
  const r = clampRisk(risk);
  if (r >= RISK_DANGEROUS_MIN) return "dangerous";
  if (r >= RISK_SAFE_MAX) return "suspicious";
  return "safe";
}

/**
 * Normalise a score to 0-1 risk regardless of the scale it arrived in.
 * @param {number} score
 * @param {"unit"|"percent"} [scale]
 * @returns {number} risk in [0, 1]
 */
export function riskFromScore(score, scale = "unit") {
  const n = Number(score);
  if (!Number.isFinite(n)) return 0;
  return clampRisk(scale === "percent" ? 1 - n / 100 : n);
}

/**
 * Map a 0-1 risk to the 0-100 trust score shown in the badge and popup.
 * @param {number} risk
 * @returns {number} integer 0-100, higher = safer
 */
export function scoreFromRisk(risk) {
  return Math.round((1 - clampRisk(risk)) * 100);
}

/**
 * Build one reason object in the extension's internal shape.
 * @param {string} code stable snake_case key (the i18n key)
 * @param {string} text one plain sentence
 * @param {"low"|"medium"|"high"} [severity]
 * @param {object} [details]
 */
export function reason(code, text, severity = "medium", details) {
  const sev = SEVERITIES.includes(severity) ? severity : "medium";
  const out = { code: String(code || "unknown"), severity: sev, text: String(text || "") };
  if (details && typeof details === "object") out.details = details;
  return out;
}

/**
 * Backend engine names -> stable reason codes, so backend reasons can be
 * localised by features/multilingual-alerts style catalogs.
 */
export const ENGINE_CODES = {
  certificate_chain: "bad_certificate",
  domain_lookalike: "brand_impersonation",
  brand_match: "brand_impersonation",
  reputation: "blocklisted",
  content_heuristics: "suspicious_page_content",
  transport: "insecure_http",
  dns_history: "new_domain",
  redirect_chain: "too_many_hops",
  url_ml: "suspicious_url_pattern",
};

/**
 * Severity mapping: the backend vocabulary adds "info".
 * @param {string} severity
 * @returns {"low"|"medium"|"high"}
 */
export function normalizeSeverity(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "high";
  if (s === "low" || s === "info") return "low";
  return "medium";
}

/**
 * Convert a POST /analyze response into the internal shape.
 * @param {object} result
 * @returns {{url: string, risk: number, verdict: string, score: number, reasons: Array, sources: string[]}}
 */
export function fromAnalyze(result) {
  const payload = result && typeof result === "object" ? result : {};
  const risk = riskFromScore(payload.score, "percent");
  const list = Array.isArray(payload.reasons) && payload.reasons.length > 0
    ? payload.reasons
    : (payload.engines || []).flatMap((engine) =>
        (engine.reasons || []).map((r) => ({ engine: engine.name, severity: r.severity, text: r.text }))
      );

  const reasons = [];
  for (const item of list) {
    if (!item || typeof item.text !== "string" || !item.text.trim()) continue;
    const code = ENGINE_CODES[item.engine] || "backend_reason";
    reasons.push(reason(code, item.text, normalizeSeverity(item.severity), item.engine ? { engine: item.engine } : undefined));
  }

  return {
    url: String(payload.url || ""),
    risk,
    verdict: verdictFromRisk(risk),
    score: scoreFromRisk(risk),
    reasons,
    sources: Array.isArray(payload.engines) ? payload.engines.map((e) => e && e.name).filter(Boolean) : [],
  };
}

/**
 * Convert a POST /scan response (features/shared schema) into the internal shape.
 * @param {object} result
 */
export function fromScan(result) {
  const payload = result && typeof result === "object" ? result : {};
  const risk = clampRisk(payload.score);
  const reasons = (Array.isArray(payload.reasons) ? payload.reasons : [])
    .map((r) =>
      r && typeof r === "object"
        ? reason(r.code || "unknown", r.message || r.text || "", normalizeSeverity(r.severity), r.details)
        : null
    )
    .filter((r) => r && r.text);

  return {
    url: String(payload.url || ""),
    risk,
    verdict: verdictFromRisk(risk),
    score: scoreFromRisk(risk),
    reasons,
    sources: [String(payload.level || "")].filter(Boolean),
    components: payload.components || null,
    checks: payload.checks || null,
    certificate: payload.certificate || null,
    redirects: payload.redirects || null,
    intel: payload.intel || null,
  };
}

/**
 * Merge the local (offline) verdict with the remote one.
 *
 * The local check can only add risk: it never talks itself out of a remote
 * finding, and the remote result never hides a high-severity local signal.
 * Reasons are de-duplicated by code + text, strongest first.
 *
 * @param {object} local internal shape from lib/triage.js (or null)
 * @param {object} remote internal shape from fromAnalyze (or null)
 */
export function combine(local, remote) {
  const a = local && typeof local === "object" ? local : null;
  const b = remote && typeof remote === "object" ? remote : null;
  if (!a && !b) {
    return { url: "", risk: 0, verdict: "safe", score: 100, reasons: [], sources: [] };
  }

  const risk = clampRisk(Math.max(a ? a.risk : 0, b ? b.risk : 0));
  const seen = new Set();
  const reasons = [];
  for (const item of [...((a && a.reasons) || []), ...((b && b.reasons) || [])]) {
    if (!item || !item.text) continue;
    const key = `${item.code}|${item.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    reasons.push(item);
  }
  const order = { high: 0, medium: 1, low: 2 };
  reasons.sort((x, y) => (order[x.severity] ?? 3) - (order[y.severity] ?? 3));

  return {
    url: (b && b.url) || (a && a.url) || "",
    risk,
    verdict: verdictFromRisk(risk),
    score: scoreFromRisk(risk),
    reasons,
    sources: Array.from(new Set([...((a && a.sources) || ["local"]), ...((b && b.sources) || [])])),
  };
}
