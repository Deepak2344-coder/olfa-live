/**
 * Olfa page-inspector: pure signal logic.
 *
 * The extension collects raw facts (cookies, requests, forms, storage keys,
 * fingerprint API calls) with chrome.* APIs and content scripts, then hands
 * them here. Keeping the judgement pure makes it testable without a browser —
 * and the same function can be imported by the core backend later.
 *
 * Inputs are plain JSON. Nothing here ever sees a cookie *value*: the collector
 * must strip values before they reach this module, and the tests assert it.
 */
(function (root) {
  'use strict';

  const schema =
    root.OlfaSchema ||
    (typeof require === 'function' ? require('./risk-schema.js') : null) || {
      reason: (code, message, severity, details) => ({ code, message, severity, details }),
      makeResult: (url, score, reasons) => ({
        url,
        score: Math.round(score * 10000) / 10000,
        level: score >= 0.75 ? 'dangerous' : score >= 0.4 ? 'suspicious' : 'safe',
        reasons,
      }),
    };

  const KNOWN_TRACKERS = [
    'doubleclick.net',
    'googlesyndication.com',
    'google-analytics.com',
    'googletagmanager.com',
    'facebook.net',
    'connect.facebook.net',
    'hotjar.com',
    'mixpanel.com',
    'segment.io',
    'amplitude.com',
    'criteo.com',
    'taboola.com',
    'outbrain.com',
    'scorecardresearch.com',
    'quantserve.com',
    'adnxs.com',
    'pubmatic.com',
    'rubiconproject.com',
  ];

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  }

  function isThirdParty(requestUrl, pageHost) {
    const host = hostOf(requestUrl);
    if (!host) return false;
    return host !== pageHost && !host.endsWith('.' + pageHost);
  }

  function isKnownTracker(host) {
    return KNOWN_TRACKERS.some((t) => host === t || host.endsWith('.' + t));
  }

  /** Card-number-ish and password field names/autocomplete values. */
  const CARD_HINTS = ['card', 'cc-number', 'ccnumber', 'creditcard', 'cvv', 'cvc', 'expiry', 'pan'];
  const PASSWORD_HINTS = ['password', 'passwd', 'pass', 'pwd'];

  function looksLikePassword(field) {
    const hay = [field.type, field.name, field.autocomplete, field.id].filter(Boolean).join(' ').toLowerCase();
    return field.type === 'password' || PASSWORD_HINTS.some((h) => hay.includes(h));
  }

  function looksLikeCard(field) {
    const hay = [field.type, field.name, field.autocomplete, field.id].filter(Boolean).join(' ').toLowerCase();
    return CARD_HINTS.some((h) => hay.includes(h));
  }

  /**
   * @param {object} facts
   *   {pageUrl, cookies: [{name, domain, secure, httpOnly, sameSite, expires}],
   *    requests: [{url, method, type}], forms: [{action, method, pageUrl, fields:[...]}],
   *    storageKeys: {local: [...], session: [...]}, fingerprintCalls: [string]}
   */
  function analyze(facts) {
    const pageUrl = facts.pageUrl || '';
    const pageHost = hostOf(pageUrl);
    const reasons = [];
    const signals = {};

    /* --- cookies ------------------------------------------------------ */
    const cookies = facts.cookies || [];
    const insecureCookies = cookies.filter((c) => !c.secure);
    const thirdPartyCookies = cookies.filter((c) => {
      const d = String(c.domain || '').replace(/^\./, '').toLowerCase();
      return d && pageHost && d !== pageHost && !pageHost.endsWith('.' + d);
    });
    const trackerCookies = cookies.filter((c) => isKnownTracker(String(c.domain || '').replace(/^\./, '').toLowerCase()));

    if (insecureCookies.length) {
      signals.cookies_missing_secure = insecureCookies.length;
      reasons.push(
        schema.reason(
          'cookies_missing_secure',
          `${insecureCookies.length} cookie(s) are not marked Secure, so they can leak over plain http.`,
          'medium',
          { names: insecureCookies.slice(0, 5).map((c) => c.name) }
        )
      );
    }
    if (thirdPartyCookies.length) {
      signals.third_party_cookies = thirdPartyCookies.length;
      reasons.push(
        schema.reason(
          'third_party_cookies',
          `${thirdPartyCookies.length} cookie(s) belong to other domains and can follow you across sites.`,
          'low',
          { domains: Array.from(new Set(thirdPartyCookies.map((c) => c.domain))).slice(0, 5) }
        )
      );
    }
    if (trackerCookies.length) {
      signals.known_tracker_cookies = trackerCookies.length;
      reasons.push(
        schema.reason(
          'known_tracker',
          `Recognised tracking cookies from ${Array.from(new Set(trackerCookies.map((c) => c.domain))).join(', ')}.`,
          'low',
          { domains: Array.from(new Set(trackerCookies.map((c) => c.domain))) }
        )
      );
    }

    /* --- requests ----------------------------------------------------- */
    const requests = facts.requests || [];
    const thirdParty = requests.filter((r) => isThirdParty(r.url, pageHost));
    const thirdPartyHosts = Array.from(new Set(thirdParty.map((r) => hostOf(r.url))));
    const trackerHosts = thirdPartyHosts.filter(isKnownTracker);
    const crossOriginPosts = thirdParty.filter((r) => String(r.method || 'GET').toUpperCase() === 'POST');

    if (thirdPartyHosts.length >= 8) {
      signals.many_third_parties = thirdPartyHosts.length;
      reasons.push(
        schema.reason('many_third_parties', `This page contacts ${thirdPartyHosts.length} other domains, which spreads your data widely.`, 'medium', {
          domains: thirdPartyHosts.slice(0, 8),
        })
      );
    }
    if (trackerHosts.length) {
      signals.known_trackers = trackerHosts.length;
      reasons.push(schema.reason('known_tracker', `Requests go to known trackers: ${trackerHosts.join(', ')}.`, 'low', { domains: trackerHosts }));
    }
    if (crossOriginPosts.length) {
      signals.cross_origin_posts = crossOriginPosts.length;
      reasons.push(
        schema.reason('cross_origin_posts', `${crossOriginPosts.length} POST request(s) send data to another domain.`, 'medium', {
          targets: Array.from(new Set(crossOriginPosts.map((r) => hostOf(r.url)))).slice(0, 5),
        })
      );
    }

    /* --- forms -------------------------------------------------------- */
    const forms = facts.forms || [];
    for (const form of forms) {
      const fields = form.fields || [];
      const hasSecret = fields.some((f) => looksLikePassword(f) || looksLikeCard(f));
      if (!hasSecret) continue;

      const actionUrl = form.action || pageUrl;
      const actionHost = hostOf(actionUrl) || pageHost;
      const crossOrigin = actionHost !== pageHost && !actionHost.endsWith('.' + pageHost);
      const overHttp = String(actionUrl).toLowerCase().startsWith('http:');

      if (crossOrigin && overHttp) {
        signals.credential_form_cross_origin = true;
        signals.credentials_over_http = true;
        reasons.push(
          schema.reason(
            'credential_form_cross_origin',
            `A password/card form posts to ${actionHost} over plain http — your details would travel unencrypted to another site.`,
            'high',
            { action: actionUrl, fields: fields.map((f) => f.name).filter(Boolean).slice(0, 5) }
          )
        );
      } else if (crossOrigin) {
        signals.credential_form_cross_origin = true;
        reasons.push(
          schema.reason(
            'credential_form_cross_origin',
            `A password/card form would send what you type to ${actionHost}, not ${pageHost}.`,
            'high',
            { action: actionUrl }
          )
        );
      } else if (overHttp) {
        signals.credentials_over_http = true;
        reasons.push(schema.reason('credentials_over_http', 'A password/card form submits without encryption (http).', 'high', { action: actionUrl }));
      }
    }

    /* --- storage + fingerprinting ------------------------------------- */
    const storageKeys = facts.storageKeys || {};
    const localKeys = storageKeys.local || [];
    const sessionKeys = storageKeys.session || [];
    if (localKeys.length) {
      signals.local_storage_keys = localKeys.length;
    }
    const fingerprint = facts.fingerprintCalls || [];
    if (fingerprint.length) {
      signals.fingerprinting = fingerprint.length;
      reasons.push(
        schema.reason(
          'fingerprinting',
          `The page reads device identifiers (${Array.from(new Set(fingerprint)).join(', ')}), often used to recognise you without cookies.`,
          'medium',
          { apis: Array.from(new Set(fingerprint)) }
        )
      );
    }

    /* --- score -------------------------------------------------------- */
    let score = 0;
    // A single high-severity finding must clear the 0.4 "suspicious" line on its
    // own: a credential form posting to another domain is not a soft signal.
    for (const r of reasons) score += r.severity === 'high' ? 0.45 : r.severity === 'medium' ? 0.18 : 0.05;
    if (signals.fingerprinting && signals.known_trackers) score += 0.1;
    score = Math.min(1, Math.round(score * 10000) / 10000);

    return {
      result: schema.makeResult(pageUrl, score, reasons, { host: pageHost, signals, collected: { cookies: cookies.length, requests: requests.length, thirdParties: thirdPartyHosts.length, forms: forms.length } }),
      signals,
    };
  }

  const api = { KNOWN_TRACKERS, analyze, hostOf, isThirdParty, isKnownTracker, looksLikePassword, looksLikeCard };
  root.OlfaInspector = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
