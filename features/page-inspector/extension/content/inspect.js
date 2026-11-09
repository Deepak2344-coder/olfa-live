/**
 * Olfa page-inspector — content script.
 *
 * Collects the parts of a page chrome.* cannot see: forms, storage keys and
 * calls to fingerprinting APIs. It never reads input values and never stores
 * cookie values.
 *
 * Runs at document_start so the fingerprint hooks are in place before page
 * scripts run; the actual collection happens when the popup asks.
 */
(function () {
  'use strict';

  const fingerprintCalls = new Set();

  /** Wrap a method so we notice the call without changing its behaviour. */
  function watch(target, prop, label) {
    if (!target || typeof target[prop] !== 'function') return;
    const original = target[prop];
    target[prop] = function () {
      fingerprintCalls.add(label);
      return original.apply(this, arguments);
    };
  }

  try {
    watch(HTMLCanvasElement.prototype, 'toDataURL', 'canvas');
    if (window.OffscreenCanvas) watch(window.OffscreenCanvas.prototype, 'convertToBlob', 'canvas');
    const Ctx = window.CanvasRenderingContext2D && window.CanvasRenderingContext2D.prototype;
    watch(Ctx, 'getImageData', 'canvas');
    if (window.AudioContext) watch(window.AudioContext.prototype, 'createOscillator', 'audio');
    if (window.webkitAudioContext) watch(window.webkitAudioContext.prototype, 'createOscillator', 'audio');
    if (navigator.permissions && navigator.permissions.query) {
      const query = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = function (desc) {
        fingerprintCalls.add('permissions');
        return query(desc);
      };
    }
  } catch (e) {
    /* defensive: a broken hook must never break the page */
  }

  function describeField(field) {
    return {
      type: (field.type || '').toLowerCase(),
      name: field.name || '',
      id: field.id || '',
      autocomplete: (field.getAttribute && field.getAttribute('autocomplete')) || '',
    };
  }

  function collectForms() {
    return Array.from(document.forms || []).map((form) => ({
      action: form.getAttribute('action') || '',
      method: (form.getAttribute('method') || 'get').toLowerCase(),
      pageUrl: location.href,
      fields: Array.from(form.elements || [])
        .filter((el) => el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT')
        .map(describeField),
    }));
  }

  function keys(store) {
    const out = [];
    try {
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i);
        if (key != null) out.push(key);
        if (out.length >= 50) break;
      }
    } catch (e) {
      /* storage can throw in partitioned contexts */
    }
    return out;
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.type !== 'olfa:inspect') return false;
    sendResponse({
      pageUrl: location.href,
      forms: collectForms(),
      storageKeys: { local: keys(localStorage), session: keys(sessionStorage) },
      fingerprintCalls: Array.from(fingerprintCalls),
    });
    return true;
  });
})();
