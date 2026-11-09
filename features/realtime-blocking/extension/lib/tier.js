/**
 * Olfa realtime-blocking: pure logic, no chrome.* calls.
 *
 * Everything here is synchronous and side-effect free so it can be unit tested
 * with `node --test` and also run inside the MV3 service worker (importScripts).
 *
 * Exposes: localCheck(url), decideTier(score, opts), isWhitelisted(host),
 * typosquat(host), heuristics(url), levenshtein(a, b)
 */
(function (root) {
  'use strict';

  // Reuse the shared schema helpers; fall back to a tiny inline copy so this
  // file never breaks if it is loaded on its own.
  const schema =
    root.OlfaSchema ||
    (typeof require === 'function' ? require('./risk-schema.js') : null) || {
      levelFromScore: (s) => (s >= 0.75 ? 'dangerous' : s >= 0.4 ? 'suspicious' : 'safe'),
      clampScore: (v) => Math.min(1, Math.max(0, Number(v) || 0)),
      reason: (code, message, severity) => ({ code, message, severity: severity || 'medium' }),
      makeResult: (url, score, reasons) => ({
        url,
        score: Math.round(score * 10000) / 10000,
        level: s2l(score),
        reasons,
      }),
    };

  function s2l(score) {
    return score >= 0.75 ? 'dangerous' : score >= 0.4 ? 'suspicious' : 'safe';
  }

  /** Exact hosts known to be malicious in this demo corpus. */
  const BLOCKLIST = [
    'paypa1-login.example',
    'sbi-kyc-update.example',
    'free-gift-claim.example',
    'secure-verify-account.example',
    'olfa-test-high.example',
  ];

  /** Domains we must never block, even when a heuristic fires. */
  const WHITELIST_SUFFIXES = [
    'gov.in',
    'nic.in',
    'edu',
    'ac.in',
    'edu.in',
    'wikipedia.org',
    'github.com',
    'google.com',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'paypal.com',
    'sbi.co.in',
    'hdfcbank.com',
    'icicibank.com',
  ];

  /** Brands a phisher is most likely to imitate. */
  const BRANDS = [
    { brand: 'paypal', domains: ['paypal.com', 'paypal.me'] },
    { brand: 'google', domains: ['google.com', 'google.co.in', 'gmail.com'] },
    { brand: 'microsoft', domains: ['microsoft.com', 'live.com', 'office.com'] },
    { brand: 'apple', domains: ['apple.com', 'icloud.com'] },
    { brand: 'amazon', domains: ['amazon.com', 'amazon.in'] },
    { brand: 'netflix', domains: ['netflix.com'] },
    { brand: 'whatsapp', domains: ['whatsapp.com'] },
    { brand: 'instagram', domains: ['instagram.com'] },
    { brand: 'facebook', domains: ['facebook.com'] },
    { brand: 'flipkart', domains: ['flipkart.com'] },
    { brand: 'paytm', domains: ['paytm.com'] },
    { brand: 'phonepe', domains: ['phonepe.com'] },
    { brand: 'sbi', domains: ['sbi.co.in', 'onlinesbi.sbi'] },
    { brand: 'hdfc', domains: ['hdfcbank.com'] },
    { brand: 'icici', domains: ['icicibank.com'] },
    { brand: 'axis', domains: ['axisbank.com'] },
  ];

  /** Cheap heuristics: each hit adds weight to the local score. */
  const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.gq', '.tk', '.ml', '.cf', '.zip', '.mov'];
  const LURE_WORDS = ['login', 'signin', 'verify', 'secure', 'update', 'account', 'kyc', 'refund', 'gift', 'prize', 'otp', 'wallet'];

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  }

  function isWhitelisted(hostname) {
    const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
    if (!h) return false;
    return WHITELIST_SUFFIXES.some((suffix) => h === suffix || h.endsWith('.' + suffix));
  }

  function isBlocklisted(hostname) {
    const h = String(hostname || '').toLowerCase();
    return BLOCKLIST.some((entry) => h === entry || h.endsWith('.' + entry));
  }

  /** Levenshtein distance with an early bail-out once `limit` is exceeded. */
  function levenshtein(a, b, limit) {
    a = String(a);
    b = String(b);
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > (limit || Infinity)) return limit || 99;
    let prev = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      let rowMin = i;
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        if (cur[j] < rowMin) rowMin = cur[j];
      }
      if (limit && rowMin > limit) return limit + 1;
      prev = cur;
    }
    return prev[b.length];
  }

  /**
   * Typosquat check on the registrable part of the hostname.
   * Returns {brand, matchedDomain, distance, official} or null.
   */
  function typosquat(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^www\./, '');
    if (!host) return null;
    const labels = host.split('.');
    const name = labels.length > 1 ? labels[labels.length - 2] : labels[0];
    for (const entry of BRANDS) {
      // Exact official domain (or subdomain) -> nothing to see here.
      if (entry.domains.some((d) => host === d || host.endsWith('.' + d))) return null;
      for (const official of entry.domains) {
        const officialName = official.split('.')[0];
        const distance = levenshtein(name, officialName, 2);
        if (distance > 0 && distance <= 2 && Math.abs(name.length - officialName.length) <= 2) {
          return { brand: entry.brand, matchedDomain: official, distance, official: false };
        }
        // Brand as a subdomain label, e.g. paypal.login-secure.xyz
        if (officialName.length >= 4 && labels.slice(0, -2).includes(officialName)) {
          return { brand: entry.brand, matchedDomain: official, distance: 0, official: false };
        }
      }
    }
    return null;
  }

  /** Heuristic signals for a URL. Returns an array of shared-schema reasons. */
  function heuristics(url) {
    const reasons = [];
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      return [schema.reason('malformed_url', 'This address could not be parsed.', 'medium')];
    }
    const host = parsed.hostname.toLowerCase();
    const path = (parsed.pathname + parsed.search).toLowerCase();

    if (parsed.username || parsed.password) {
      reasons.push(schema.reason('userinfo_in_url', 'The link hides a user name in front of the real domain, a classic disguise trick.', 'high'));
    }
    if (parsed.protocol === 'http:') {
      reasons.push(schema.reason('insecure_http', 'This page would load without encryption (http), so anything you type can be read in transit.', 'medium'));
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      reasons.push(schema.reason('ip_literal_host', 'The site is addressed by a raw IP number instead of a name.', 'high'));
    }
    if (host.startsWith('xn--') || host.includes('.xn--')) {
      reasons.push(schema.reason('punycode_host', 'The domain uses characters that can look identical to a real brand.', 'high'));
    }
    if (SUSPICIOUS_TLDS.some((tld) => host.endsWith(tld))) {
      reasons.push(schema.reason('suspicious_tld', 'This top-level domain is heavily used for throwaway phishing sites.', 'medium'));
    }
    if (host.split('.').length > 4) {
      reasons.push(schema.reason('many_subdomains', 'The address stacks many subdomains, which is used to bury the real domain.', 'medium'));
    }
    if (host.length > 30 || url.length > 90) {
      reasons.push(schema.reason('long_url', 'The address is unusually long, which usually hides where it really points.', 'low'));
    }
    const lures = LURE_WORDS.filter((w) => path.includes(w) || host.includes(w));
    if (lures.length >= 2) {
      reasons.push(schema.reason('lure_keywords', `The address uses pressure words: ${lures.slice(0, 3).join(', ')}.`, 'medium', { words: lures }));
    }
    if ((host.match(/-/g) || []).length >= 2) {
      reasons.push(schema.reason('hyphenated_domain', 'The domain chains several hyphens, typical of fake brand domains.', 'low'));
    }
    return reasons;
  }

  /** Weighted local score in [0,1] from the signals we can compute offline. */
  function scoreReasons(reasons, blocklisted) {
    let score = 0;
    for (const r of reasons) {
      score += r.severity === 'high' ? 0.42 : r.severity === 'medium' ? 0.22 : 0.08;
    }
    if (blocklisted) score = Math.max(score, 0.97);
    return Math.min(1, Math.round(score * 10000) / 10000);
  }

  /**
   * The fast check that runs on every navigation.
   * Returns {result, tier, whitelisted, blocklisted}.
   */
  function localCheck(url) {
    const host = hostOf(url);
    const whitelisted = isWhitelisted(host);
    const blocklisted = isBlocklisted(host);
    const reasons = [];

    if (blocklisted) {
      reasons.push(schema.reason('blocklisted', 'This site is on Olfa\'s confirmed blocklist.', 'high', { host }));
    }
    const squat = whitelisted ? null : typosquat(host);
    if (squat) {
      reasons.push(
        schema.reason('typosquat', `The domain imitates ${squat.brand} but is not ${squat.matchedDomain}.`, 'high', squat)
      );
    }
    if (!whitelisted) reasons.push(...heuristics(url));

    const score = scoreReasons(reasons, blocklisted);
    const tier = decideTier(score, { blocklisted, whitelisted });

    return { result: schema.makeResult(url, score, reasons, { host, local: true }), tier, whitelisted, blocklisted };
  }

  /**
   * Tier decision. This is the rule the whole extension hinges on:
   *   blocklisted or score > 0.9  -> 'block'  (full-screen warning, before load)
   *   0.4 <= score <= 0.9         -> 'warn'   (banner + cross-domain form submit blocked)
   *   score < 0.4                 -> 'log'    (silent)
   */
  function decideTier(score, opts) {
    const options = opts || {};
    if (options.whitelisted) return 'allow';
    const s = schema.clampScore(score);
    if (options.blocklisted || s > 0.9) return 'block';
    if (s >= 0.4) return 'warn';
    return 'log';
  }

  const api = {
    BLOCKLIST,
    WHITELIST_SUFFIXES,
    BRANDS,
    levenshtein,
    hostOf,
    isWhitelisted,
    isBlocklisted,
    typosquat,
    heuristics,
    scoreReasons,
    localCheck,
    decideTier,
  };

  root.OlfaTier = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
