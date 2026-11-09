// Offline URL triage: what we can say about a URL with no network at all.
//
// Ported from features/realtime-blocking/extension/lib/tier.js and rewritten as
// an ES module emitting the extension's internal shape (see lib/normalize.js).
// Runs in the service worker, the popup and plain `node --test`.
//
// Rules are deliberately conservative: the whitelist always wins, and a
// brand's own domain is never a typosquat.
import { clampRisk, reason, verdictFromRisk } from "./normalize.js";

/** Hosts confirmed malicious in this demo corpus. */
export const BLOCKLIST = [
  "paypa1-login.example",
  "sbi-kyc-update.example",
  "free-gift-claim.example",
  "secure-verify-account.example",
  "olfa-test-high.example",
];

/** Never flagged, whatever a heuristic says. */
export const WHITELIST_SUFFIXES = [
  "gov.in",
  "nic.in",
  "edu",
  "ac.in",
  "edu.in",
  "wikipedia.org",
  "github.com",
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "sbi.co.in",
  "hdfcbank.com",
  "icicibank.com",
];

/** Brands a phisher is most likely to imitate. */
export const BRANDS = [
  { brand: "paypal", domains: ["paypal.com", "paypal.me"] },
  { brand: "google", domains: ["google.com", "google.co.in", "gmail.com"] },
  { brand: "microsoft", domains: ["microsoft.com", "live.com", "office.com"] },
  { brand: "apple", domains: ["apple.com", "icloud.com"] },
  { brand: "amazon", domains: ["amazon.com", "amazon.in"] },
  { brand: "netflix", domains: ["netflix.com"] },
  { brand: "whatsapp", domains: ["whatsapp.com"] },
  { brand: "instagram", domains: ["instagram.com"] },
  { brand: "facebook", domains: ["facebook.com"] },
  { brand: "flipkart", domains: ["flipkart.com"] },
  { brand: "paytm", domains: ["paytm.com"] },
  { brand: "phonepe", domains: ["phonepe.com"] },
  { brand: "sbi", domains: ["sbi.co.in", "onlinesbi.sbi"] },
  { brand: "hdfc", domains: ["hdfcbank.com"] },
  { brand: "icici", domains: ["icicibank.com"] },
  { brand: "axis", domains: ["axisbank.com"] },
];

export const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf", ".zip", ".mov"];
export const LURE_WORDS = ["login", "signin", "verify", "secure", "update", "account", "kyc", "refund", "gift", "prize", "otp", "wallet"];

/** Severity weights, tuned so one high finding clears the 0.4 suspicious line. */
const WEIGHTS = { high: 0.42, medium: 0.22, low: 0.08 };

/**
 * Lower-cased hostname, or "" when the URL cannot be parsed.
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
 * @param {string} hostname
 * @returns {boolean}
 */
export function isWhitelisted(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host) return false;
  return WHITELIST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/**
 * @param {string} hostname
 * @returns {boolean}
 */
export function isBlocklisted(hostname) {
  const host = String(hostname || "").toLowerCase();
  return BLOCKLIST.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

/**
 * Levenshtein distance with an early bail-out once `limit` is exceeded.
 * @param {string} a
 * @param {string} b
 * @param {number} [limit]
 * @returns {number}
 */
export function levenshtein(a, b, limit) {
  const left = String(a);
  const right = String(b);
  if (left === right) return 0;
  if (limit && Math.abs(left.length - right.length) > limit) return limit + 1;

  let prev = Array.from({ length: right.length + 1 }, (_, j) => j);
  for (let i = 1; i <= left.length; i += 1) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (limit && rowMin > limit) return limit + 1;
    prev = cur;
  }
  return prev[right.length];
}

/** Two-part public suffixes, so "google.co.uk" has the site name "google", not "co". */
const MULTI_SUFFIX = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "gov.in", "nic.in", "ac.in", "edu.in", "org.in", "net.in",
  "com.au", "net.au", "org.au", "edu.au", "co.nz", "co.jp", "or.jp", "ne.jp", "co.kr", "co.za", "co.id", "co.il",
  "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg", "com.my", "com.br", "com.mx", "com.ar", "com.tr",
  "com.ua", "com.pk", "com.bd", "com.ph", "com.vn", "com.eg", "com.sa", "com.ng", "co.th",
]);

/** Customer-content hosts: "<name>.github.io" is the customer's page, not github's. */
const SHARED_HOSTS = new Set([
  "github.io", "gitlab.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "web.app", "firebaseapp.com",
  "appspot.com", "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "sites.google.com", "azurewebsites.net",
  "workers.dev", "onrender.com", "glitch.me", "repl.co", "myshopify.com", "sharepoint.com", "zendesk.com",
  "atlassian.net", "notion.site", "carrd.co", "webflow.io", "tumblr.com", "medium.com", "substack.com",
]);

/**
 * Domains that contain a brand name because they ARE that brand's plumbing
 * (googleapis.com, amazonaws.com ...). Exempt from the brand-NAME rules only.
 */
export const BRAND_INFRA = [
  "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com", "googlesyndication.com",
  "googletagmanager.com", "google-analytics.com", "doubleclick.net", "ggpht.com", "ytimg.com", "withgoogle.com",
  "youtu.be", "amazonaws.com", "cloudfront.net", "amazon-adsystem.com", "azureedge.net", "windows.net",
  "msftauth.net", "cdn-apple.com", "apple-dns.net", "fbcdn.net", "cdninstagram.com", "whatsapp.net",
  "githubusercontent.com",
];

/** Split a host into { reg, name, suffix, subs[] }. */
export function splitHost(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  const labels = host.split(".").filter(Boolean);
  if (labels.length < 2) return { host, reg: host, name: host, suffix: "", subs: [] };
  const two = labels.slice(-2).join(".");
  const n = MULTI_SUFFIX.has(two) ? 3 : 2;
  const regLabels = labels.slice(-Math.min(n, labels.length));
  return {
    host,
    reg: regLabels.join("."),
    name: regLabels[0],
    suffix: regLabels.slice(1).join("."),
    subs: labels.slice(0, labels.length - regLabels.length),
  };
}

const LEET = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", $: "s", "@": "a" };
function deleet(text) {
  return String(text).replace(/[013457$@]/g, (c) => LEET[c]);
}

function underDomain(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

/** A ccTLD-style suffix: "uk", "co.uk", "com.cn" ... (never .xyz/.top). */
function isCountrySuffix(suffix) {
  const last = suffix.split(".").pop();
  return last.length === 2 && !SUSPICIOUS_TLDS.includes(`.${suffix}`);
}

/**
 * Brand look-alike check, judged on the site's own name, never on whichever
 * label happens to sit second from the right.
 *
 *   high   - digit swap (paypa1), brand glued to words (paypal-login-secure),
 *            brand as a subdomain of a foreign site (paypal.login-secure.xyz),
 *            brand's own name on a throwaway TLD (paypal.xyz)
 *   medium - one letter off a 5+ letter brand (may be an ordinary word), or a
 *            customer page on a shared host named after a brand
 * A brand's own name on another country suffix (google.co.uk) is not imitation.
 *
 * @param {string} hostname
 * @returns {{brand: string, matchedDomain: string, distance: number, severity: "high"|"medium"} | null}
 */
export function typosquat(hostname) {
  const { host, reg, name, suffix, subs } = splitHost(hostname);
  if (!host || !name || /^\d+(\.\d+)*$/.test(host)) return null;
  if (BRAND_INFRA.some((d) => underDomain(host, d))) return null;
  if (BRANDS.some((e) => e.domains.some((d) => underDomain(host, d)))) return null;

  const shared = SHARED_HOSTS.has(reg);
  const flat = deleet(name);
  let best = null;
  const keep = (hit) => {
    if (!best || (hit.severity === "high" && best.severity !== "high")) best = hit;
  };

  for (const entry of BRANDS) {
    for (const official of entry.domains) {
      const officialName = official.split(".")[0];
      if (officialName.length < 4) continue;
      const hit = (severity, distance) => ({ brand: entry.brand, matchedDomain: official, distance, severity });

      if (name === officialName) {
        // google.co.uk is Google; paypal.xyz is not PayPal.
        if (!shared && !isCountrySuffix(suffix) && SUSPICIOUS_TLDS.includes(`.${suffix.split(".").pop()}`)) keep(hit("high", 0));
        continue;
      }
      if (!shared && flat === officialName && name !== flat) { keep(hit("high", 1)); continue; }
      if (!shared && name.split("-").some((part) => part === officialName || deleet(part) === officialName) && name.includes("-")) {
        keep(hit("high", 0));
        continue;
      }
      if (subs.some((label) => label === officialName)) {
        keep(hit(shared ? "medium" : "high", 0));
        continue;
      }
      if (!shared && officialName.length >= 5 && levenshtein(flat, officialName, 1) === 1) keep(hit("medium", 1));
    }
  }
  return best;
}

/**
 * Heuristic signals for one URL.
 * @param {string} url
 * @param {string} [hostname] already-parsed host (saves a parse)
 * @returns {Array<object>} internal reason objects
 */
export function heuristics(url, hostname) {
  const reasons = [];
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return [reason("malformed_url", "This address could not be parsed.", "medium")];
  }

  const host = (hostname || parsed.hostname).toLowerCase();
  const path = `${parsed.pathname}${parsed.search}`.toLowerCase();

  if (parsed.username || parsed.password) {
    reasons.push(reason("userinfo_in_url", "The link hides a user name in front of the real domain, a classic disguise trick.", "high"));
  }
  if (parsed.protocol === "http:") {
    reasons.push(reason("insecure_http", "This page would load without encryption (http), so anything you type can be read in transit.", "medium"));
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    reasons.push(reason("ip_literal_host", "The site is addressed by a raw IP number instead of a name.", "high"));
  }
  if (host.startsWith("xn--") || host.includes(".xn--")) {
    reasons.push(reason("punycode_host", "The domain uses characters that can look identical to a real brand.", "high"));
  }
  if (SUSPICIOUS_TLDS.some((tld) => host.endsWith(tld))) {
    reasons.push(reason("suspicious_tld", "This top-level domain is heavily used for throwaway phishing sites.", "medium"));
  }
  if (host.split(".").length > 4) {
    reasons.push(reason("many_subdomains", "The address stacks many subdomains, which is used to bury the real domain.", "medium"));
  }
  if (host.length > 30 || url.length > 90) {
    reasons.push(reason("long_url", "The address is unusually long, which usually hides where it really points.", "low"));
  }
  const lures = LURE_WORDS.filter((word) => path.includes(word) || host.includes(word));
  if (lures.length >= 2) {
    reasons.push(reason("lure_keywords", `The address uses pressure words: ${lures.slice(0, 3).join(", ")}.`, "medium", { words: lures }));
  }
  if ((host.match(/-/g) || []).length >= 2) {
    reasons.push(reason("hyphenated_domain", "The domain chains several hyphens, typical of fake brand domains.", "low"));
  }
  return reasons;
}

/**
 * Weighted local risk in [0, 1].
 * @param {Array<object>} reasons
 * @param {boolean} blocklisted
 * @returns {number}
 */
export function scoreReasons(reasons, blocklisted) {
  let score = 0;
  for (const item of reasons) score += WEIGHTS[item.severity] ?? WEIGHTS.medium;
  if (blocklisted) score = 0.97;
  return clampRisk(score);
}

/**
 * The check that runs on every navigation, before (and without) the network.
 * @param {string} url
 * @returns {{url: string, risk: number, verdict: string, score: number, reasons: Array, whitelisted: boolean, blocklisted: boolean}}
 */
export function localCheck(url) {
  const host = hostOf(url);
  const whitelisted = isWhitelisted(host);
  const blocklisted = isBlocklisted(host);
  const reasons = [];

  if (blocklisted) {
    reasons.push(reason("blocklisted", "This site is on the confirmed blocklist.", "high", { host }));
  }

  const squat = whitelisted ? null : typosquat(host);
  if (squat) {
    reasons.push(reason("typosquat", `The domain imitates ${squat.brand} but is not ${squat.matchedDomain}.`, squat.severity || "high", squat));
  }
  if (!whitelisted) reasons.push(...heuristics(url, host));

  const risk = scoreReasons(reasons, blocklisted);
  return {
    url: String(url || ""),
    risk,
    verdict: verdictFromRisk(risk),
    score: Math.round((1 - risk) * 100),
    reasons,
    whitelisted,
    blocklisted,
  };
}
