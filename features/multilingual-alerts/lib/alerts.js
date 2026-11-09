/**
 * Olfa multilingual-alerts — catalog of warning copy in EN/HI/BN,
 * keyed by reason code, and a getAlert(reason) helper.
 *
 * The catalog lives as plain JSON objects so it can be shipped static‑wise
 * with the feature and also required in Node tests without a server.
 *
 * Reason codes (shared across all languages, per the shared risk-schema):
 *   PHISH_URL        – fake login page
 *   TYPOSQUAT        – look‑alike domain
 *   URGENT_POPUP     – "your account will be closed"
 *   INVALID_CERT     – self‑signed / expired cert
 *   COOKIE_TRACK     – aggressive tracking
 *
 * Each reason code maps to a translated string in each language.
 */

const enCatalog = {
  PHISH_URL: 'Warning: This page impersonates a login screen.',
  TYPOSQUAT: 'Warning: The domain looks similar to a known brand.',
  URGENT_POPUP: 'Warning: You are being urged to act quickly.',
  INVALID_CERT: 'Warning: The site certificate is invalid or expired.',
  COOKIE_TRACK: 'Warning: This site sets aggressive tracking cookies.',
};

const hiCatalog = {
  PHISH_URL: 'चेतावनी: यह पृष्ठ लॉगिन स्क्रीन की नकल कर रहा है।',
  TYPOSQUAT: 'चेतावनी: डोमेन एक प्रसिद्ध ब्रांड जैसा दिखता है।',
  URGENT_POPUP: 'चेतावनी: आपको जल्दी काम करने के लिए उकसाया जा रहा है।',
  INVALID_CERT: 'चेतावनी: साइट का प्रमाणपत्र 무ült या समाप्त हो गया है।',
  COOKIE_TRACK: 'चेतावनी: इस साइट ने आक्रामक ट्रैकिंग कुकीज़ सेट की हैं।',
};

const bnCatalog = {
  PHISH_URL: 'সতর্কতা: এই পৃষ্ঠাটি লগইন স্ক্রিনের নকল।',
  TYPOSQUAT: 'সতর্কতা: ডোমেইন извест ব্যান্ডের মতো দেখে।',
  URGENT_POPUP: 'সতর্কতা: আপনাকে ত velocitàে কাজ করার জন্য উকসা হচ্ছে।',
  INVALID_CERT: 'সতর্কতা: সাইটের সার্টিফিকেট বৈধ নেই বা সমাপ্ত হয়েছে।',
  COOKIE_TRACK: 'সতর্কতা: এই সাইটে aggressive tracking cookies set কiye গেছে।',
};

/** Return the translated warning string for a given reason code and language. */
function getAlert(reason, language = 'en') {
  const catalog = { en: enCatalog, hi: hiCatalog, bn: bnCatalog }[language];
  if (!catalog) {
    console.warn(`Unknown language "${language}", falling back to English.`);
    return enCatalog[reason] || 'Unknown warning.';
  }
  const text = catalog[reason];
  if (!text) {
    return 'Warning: unknown risk.';
  }
  return text;
}

/** List all reason codes that have translations in the given language. */
function listReasons(language = 'en') {
  const catalog = { en: enCatalog, hi: hiCatalog, bn: bnCatalog }[language];
  return catalog ? Object.keys(catalog) : [];
}

/** Validate that a reason code exists in the given language's catalog. */
function validateReason(reason, language = 'en') {
  const catalog = { en: enCatalog, hi: hiCatalog, bn: bnCatalog }[language];
  if (!catalog) return false;
  return reason in catalog;
}

// Export (CJS for compatibility; browser can also use via globalThis).
module.exports = { getAlert, listReasons, validateReason };

if (typeof globalThis !== 'undefined') {
  globalThis.OlfaAlerts = { getAlert, listReasons, validateReason };
}