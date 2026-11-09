// Page signals: cookies, third-party requests, forms, storage and
// fingerprinting, turned into risk + reasons.
//
// Ported from features/page-inspector/extension/lib/signals.js.
//
// PRIVACY CONTRACT (enforced by tests/signals.test.mjs):
//   * cookie VALUES never reach this module — the collector strips them;
//   * form fields are described by name/type/autocomplete, never by value;
//   * requests carry URL + method + type only, no headers or bodies.
import { clampRisk, reason, verdictFromRisk } from "./normalize.js";

export const KNOWN_TRACKERS = [
  "doubleclick.net",
  "googlesyndication.com",
  "google-analytics.com",
  "googletagmanager.com",
  "connect.facebook.net",
  "facebook.net",
  "hotjar.com",
  "mixpanel.com",
  "segment.io",
  "amplitude.com",
  "criteo.com",
  "taboola.com",
  "outbrain.com",
  "scorecardresearch.com",
  "quantserve.com",
  "adnxs.com",
  "pubmatic.com",
  "rubiconproject.com",
];

const CARD_HINTS = ["card", "cc-number", "ccnumber", "creditcard", "cvv", "cvc", "expiry", "pan"];
const PASSWORD_HINTS = ["password", "passwd", "pass", "pwd"];
const WEIGHTS = { high: 0.45, medium: 0.18, low: 0.05 };

/**
 * @param {string} url
 * @returns {string}
 */
export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * @param {string} requestUrl
 * @param {string} pageHost
 * @returns {boolean}
 */
export function isThirdParty(requestUrl, pageHost) {
  const host = hostOf(requestUrl);
  if (!host || !pageHost) return false;
  return host !== pageHost && !host.endsWith(`.${pageHost}`) && !pageHost.endsWith(`.${host}`);
}

/**
 * @param {string} host
 * @returns {boolean}
 */
export function isKnownTracker(host) {
  const h = String(host || "").toLowerCase().replace(/^\./, "");
  return KNOWN_TRACKERS.some((tracker) => h === tracker || h.endsWith(`.${tracker}`));
}

function fieldHaystack(field) {
  const f = field || {};
  return [f.type, f.name, f.autocomplete, f.id].filter(Boolean).join(" ").toLowerCase();
}

/**
 * @param {object} field
 * @returns {boolean}
 */
export function looksLikePassword(field) {
  const f = field || {};
  return f.type === "password" || PASSWORD_HINTS.some((hint) => fieldHaystack(f).includes(hint));
}

/**
 * @param {object} field
 * @returns {boolean}
 */
export function looksLikeCard(field) {
  return CARD_HINTS.some((hint) => fieldHaystack(field).includes(hint));
}

/**
 * An empty facts object, so callers can always spread into it.
 */
export function emptyFacts() {
  return { pageUrl: "", cookies: [], requests: [], forms: [], storageKeys: { local: [], session: [] }, fingerprintCalls: [] };
}

/**
 * Judge collected page facts.
 *
 * @param {object} facts
 *   {pageUrl, cookies: [{name, domain, secure, httpOnly, sameSite, expires}],
 *    requests: [{url, method, type}], forms: [{action, method, fields: [{name, type, autocomplete, id}]}],
 *    storageKeys: {local: string[], session: string[]}, fingerprintCalls: string[]}
 * @returns {{url: string, risk: number, verdict: string, score: number, reasons: Array, signals: object, collected: object}}
 */
export function analyzeSignals(facts) {
  const input = { ...emptyFacts(), ...(facts || {}) };
  const pageUrl = String(input.pageUrl || "");
  const pageHost = hostOf(pageUrl);
  const reasons = [];
  const signals = {};

  /* --- cookies ------------------------------------------------------- */
  const cookies = Array.isArray(input.cookies) ? input.cookies : [];
  const insecure = cookies.filter((c) => c && c.secure === false);
  const thirdParty = cookies.filter((c) => {
    const domain = String((c && c.domain) || "").replace(/^\./, "").toLowerCase();
    return Boolean(domain && pageHost && domain !== pageHost && !pageHost.endsWith(`.${domain}`));
  });
  const trackers = cookies.filter((c) => isKnownTracker(String((c && c.domain) || "")));

  if (insecure.length) {
    signals.cookies_missing_secure = insecure.length;
    reasons.push(
      reason("cookies_missing_secure", `${insecure.length} cookie(s) are not marked Secure, so they can leak over plain http.`, "medium", {
        names: insecure.slice(0, 5).map((c) => c.name),
      })
    );
  }
  if (thirdParty.length) {
    signals.third_party_cookies = thirdParty.length;
    reasons.push(
      reason("third_party_cookies", `${thirdParty.length} cookie(s) belong to other domains and can follow you across sites.`, "low", {
        domains: Array.from(new Set(thirdParty.map((c) => c.domain))).slice(0, 5),
      })
    );
  }
  if (trackers.length) {
    signals.known_tracker_cookies = trackers.length;
    reasons.push(
      reason("known_tracker", `Recognised tracking cookies from ${Array.from(new Set(trackers.map((c) => c.domain))).join(", ")}.`, "low", {
        domains: Array.from(new Set(trackers.map((c) => c.domain))),
      })
    );
  }

  /* --- requests ------------------------------------------------------ */
  const requests = Array.isArray(input.requests) ? input.requests : [];
  const external = requests.filter((r) => r && isThirdParty(r.url, pageHost));
  const externalHosts = Array.from(new Set(external.map((r) => hostOf(r.url)).filter(Boolean)));
  const trackerHosts = externalHosts.filter(isKnownTracker);
  const crossOriginPosts = external.filter((r) => String(r.method || "GET").toUpperCase() === "POST");

  if (externalHosts.length >= 8) {
    signals.many_third_parties = externalHosts.length;
    reasons.push(
      reason("many_third_parties", `This page contacts ${externalHosts.length} other domains, which spreads your data widely.`, "medium", {
        domains: externalHosts.slice(0, 8),
      })
    );
  }
  if (trackerHosts.length) {
    signals.known_trackers = trackerHosts.length;
    reasons.push(reason("known_tracker", `Requests go to known trackers: ${trackerHosts.join(", ")}.`, "low", { domains: trackerHosts }));
  }
  if (crossOriginPosts.length) {
    signals.cross_origin_posts = crossOriginPosts.length;
    reasons.push(
      reason("cross_origin_posts", `${crossOriginPosts.length} POST request(s) send data to another domain.`, "medium", {
        targets: Array.from(new Set(crossOriginPosts.map((r) => hostOf(r.url)))).slice(0, 5),
      })
    );
  }

  /* --- forms --------------------------------------------------------- */
  const forms = Array.isArray(input.forms) ? input.forms : [];
  for (const form of forms) {
    if (!form || typeof form !== "object") continue;
    const fields = Array.isArray(form.fields) ? form.fields : [];
    if (!fields.some((f) => looksLikePassword(f) || looksLikeCard(f))) continue;

    const actionUrl = String(form.action || pageUrl);
    const actionHost = hostOf(actionUrl) || pageHost;
    const crossOrigin = Boolean(actionHost && pageHost && actionHost !== pageHost && !actionHost.endsWith(`.${pageHost}`));
    const overHttp = actionUrl.toLowerCase().startsWith("http:");

    if (crossOrigin && overHttp) {
      signals.credential_form_cross_origin = true;
      signals.credentials_over_http = true;
      reasons.push(
        reason(
          "credential_form_cross_origin",
          `A password/card form posts to ${actionHost} over plain http — your details would travel unencrypted to another site.`,
          "high",
          { action: actionUrl, fields: fields.map((f) => f && f.name).filter(Boolean).slice(0, 5) }
        )
      );
    } else if (crossOrigin) {
      signals.credential_form_cross_origin = true;
      reasons.push(
        reason("credential_form_cross_origin", `A password/card form would send what you type to ${actionHost}, not ${pageHost}.`, "high", {
          action: actionUrl,
        })
      );
    } else if (overHttp) {
      signals.credentials_over_http = true;
      reasons.push(reason("credentials_over_http", "A password/card form submits without encryption (http).", "high", { action: actionUrl }));
    }
  }

  /* --- storage + fingerprinting -------------------------------------- */
  const storage = input.storageKeys && typeof input.storageKeys === "object" ? input.storageKeys : {};
  const localKeys = Array.isArray(storage.local) ? storage.local : [];
  if (localKeys.length) signals.local_storage_keys = localKeys.length;

  const fingerprint = Array.isArray(input.fingerprintCalls) ? input.fingerprintCalls.filter(Boolean) : [];
  if (fingerprint.length) {
    signals.fingerprinting = fingerprint.length;
    reasons.push(
      reason(
        "fingerprinting",
        `The page reads device identifiers (${Array.from(new Set(fingerprint)).join(", ")}), often used to recognise you without cookies.`,
        "medium",
        { apis: Array.from(new Set(fingerprint)) }
      )
    );
  }

  /* --- risk ---------------------------------------------------------- */
  let risk = 0;
  for (const item of reasons) risk += WEIGHTS[item.severity] ?? WEIGHTS.medium;
  if (signals.fingerprinting && signals.known_trackers) risk += 0.1;
  risk = clampRisk(risk);

  return {
    url: pageUrl,
    risk,
    verdict: verdictFromRisk(risk),
    score: Math.round((1 - risk) * 100),
    reasons,
    signals,
    collected: {
      cookies: cookies.length,
      requests: requests.length,
      thirdParties: externalHosts.length,
      forms: forms.length,
    },
  };
}
