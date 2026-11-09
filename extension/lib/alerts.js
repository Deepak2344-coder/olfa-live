// Localised warning copy keyed by reason code (en / hi / bn).
//
// Replaces features/multilingual-alerts, whose catalogs are keyed by five
// UPPERCASE codes (PHISH_URL, TYPOSQUAT, ...) that never match the shared
// schema's lowercase snake_case codes (typosquat, brand_impersonation, ...).
// Here the keys are the codes the extension actually emits, so a real reason
// always finds its translation.
//
// Hindi and Bengali cover the codes a user sees most often; anything else falls
// back to English, then to a level-based sentence. Deliberately no machine
// translation: a wrong warning is worse than an English one.
import { SEVERITIES } from "./normalize.js";

export const LANGUAGES = ["en", "hi", "bn"];
export const LANGUAGE_NAMES = { en: "English", hi: "हिन्दी", bn: "বাংলা" };

const en = {
  blocklisted: "This site is on the confirmed phishing blocklist.",
  typosquat: "The domain imitates a well-known brand but is not that brand.",
  brand_impersonation: "The page claims a brand the domain does not belong to.",
  insecure_http: "This page is not encrypted, so what you type can be read in transit.",
  ip_literal_host: "The site uses a raw IP address instead of a name.",
  punycode_host: "The domain uses look-alike characters to fake a real name.",
  suspicious_tld: "This top-level domain is heavily used for throwaway phishing sites.",
  many_subdomains: "The address stacks subdomains to bury the real domain.",
  long_url: "The address is unusually long, which usually hides where it goes.",
  lure_keywords: "The address uses pressure words like login, verify or refund.",
  hyphenated_domain: "The domain chains hyphens, typical of fake brand domains.",
  userinfo_in_url: "The link hides a user name in front of the real domain.",
  malformed_url: "This address could not be parsed.",
  cookies_missing_secure: "Some cookies are not marked Secure and can leak over plain http.",
  third_party_cookies: "Cookies from other domains can follow you across sites.",
  known_tracker: "Recognised advertising or analytics trackers are loaded here.",
  many_third_parties: "The page contacts many other domains, spreading your data widely.",
  cross_origin_posts: "Data you submit is posted to another domain.",
  credential_form_cross_origin: "A password or card form sends what you type to a different site.",
  credentials_over_http: "A password or card form submits without encryption.",
  fingerprinting: "The page reads device identifiers to recognise you without cookies.",
  hidden_iframe: "Invisible iframes are hidden in this page, a common clickjacking setup.",
  clickjacking_overlay: "A transparent layer covers the page and can steal your clicks.",
  obfuscated_script: "Packed or obfuscated scripts hide what the page really does.",
  keystroke_exfiltration: "Key events and a data-copying API are used together.",
  clipboard_hijack: "The page touches your clipboard.",
  risky_permission_request: "The page asks for extra browser permissions.",
  bad_certificate: "The site's TLS certificate is invalid, expired or self-signed.",
  new_domain: "The domain was registered very recently.",
  too_many_hops: "The link bounces through many redirects.",
  shortener_used: "The link hides its destination behind a URL shortener.",
  https_downgrade: "The chain drops from https to unencrypted http.",
  redirect_loop: "The link redirects in a loop.",
  qr_risky_payload: "A QR code on this page points at a risky URL.",
  suspicious_url_pattern: "The URL structure matches known phishing patterns.",
  suspicious_page_content: "The page content matches known phishing patterns.",
  backend_reason: "The trust service flagged this page.",
  unsafe_link: "A link on this page points somewhere unsafe.",
  unknown: "Something about this page looked wrong.",
};

const hi = {
  blocklisted: "यह साइट पुष्ट फ़िशिंग ब्लॉकलिस्ट में है।",
  typosquat: "यह डोमेन किसी जाने-माने ब्रांड की नकल है, वह ब्रांड नहीं।",
  brand_impersonation: "पेज किसी ब्रांड का नाम दिखा रहा है जिसका यह डोमेन नहीं है।",
  insecure_http: "यह पेज एन्क्रिप्टेड नहीं है, आपका टाइप किया डेटा पढ़ा जा सकता है।",
  suspicious_tld: "यह टॉप-लेवल डोमेन फ़िशिंग साइटों के लिए बहुत इस्तेमाल होता है।",
  lure_keywords: "पते में login, verify, refund जैसे दबाव वाले शब्द हैं।",
  cookies_missing_secure: "कुछ कुकीज़ Secure नहीं हैं और http पर लीक हो सकती हैं।",
  known_tracker: "यहाँ ज्ञात विज्ञापन या एनालिटिक्स ट्रैकर लोड होते हैं।",
  credential_form_cross_origin: "पासवर्ड या कार्ड फ़ॉर्म आपका डेटा किसी दूसरी साइट पर भेजता है।",
  credentials_over_http: "पासवर्ड या कार्ड फ़ॉर्म बिना एन्क्रिप्शन जमा होता है।",
  fingerprinting: "पेज कुकीज़ के बिना आपको पहचानने के लिए डिवाइस आईडी पढ़ता है।",
  hidden_iframe: "पेज में अदृश्य iframe छिपे हैं, यह क्लिकजैकिंग का तरीका है।",
  clickjacking_overlay: "पेज पर पारदर्शी परत आपके क्लिक चुरा सकती है।",
  obfuscated_script: "छिपी या ऑबफ़स्केटेड स्क्रिप्ट छुपाती हैं कि पेज क्या करता है।",
  bad_certificate: "साइट का TLS प्रमाणपत्र अमान्य, समाप्त या स्व-हस्ताक्षरित है।",
  new_domain: "यह डोमेन बहुत हाल में रजिस्टर हुआ है।",
  qr_risky_payload: "इस पेज का QR कोड किसी जोखिम भरे URL पर जाता है।",
  unsafe_link: "इस पेज का एक लिंक असुरक्षित जगह जाता है।",
};

const bn = {
  blocklisted: "এই সাইটটি নিশ্চিত ফিশিং ব্লকলিস্টে আছে।",
  typosquat: "এই ডোমেইনটি একটি পরিচিত ব্র্যান্ডের নকল, সেই ব্র্যান্ড নয়।",
  brand_impersonation: "পৃষ্ঠাটি এমন ব্র্যান্ডের নাম দেখাচ্ছে যা এই ডোমেইনের নয়।",
  insecure_http: "এই পৃষ্ঠা এনক্রিপ্টেড নয়, আপনি যা লেখেন তা পড়া যেতে পারে।",
  suspicious_tld: "এই টপ-লেভেল ডোমেইন ফিশিং সাইটে বহুল ব্যবহৃত।",
  lure_keywords: "ঠিকানায় login, verify, refund ধরনের চাপ তৈরি করা শব্দ আছে।",
  cookies_missing_secure: "কিছু কুকি Secure নয়, http-তে ফাঁস হতে পারে।",
  known_tracker: "এখানে পরিচিত বিজ্ঞাপন বা অ্যানালিটিক্স ট্র্যাকার লোড হয়।",
  credential_form_cross_origin: "পাসওয়ার্ড বা কার্ড ফর্ম আপনার তথ্য অন্য সাইটে পাঠায়।",
  credentials_over_http: "পাসওয়ার্ড বা কার্ড ফর্ম এনক্রিপশন ছাড়াই জমা হয়।",
  fingerprinting: "পৃষ্ঠাটি কুকি ছাড়াই আপনাকে চিনতে ডিভাইস আইডি পড়ে।",
  hidden_iframe: "পৃষ্ঠায় অদৃশ্য iframe লুকানো আছে, এটি ক্লিকজ্যাকিংয়ের কৌশল।",
  clickjacking_overlay: "পৃষ্ঠার উপর স্বচ্ছ স্তর আপনার ক্লিক চুরি করতে পারে।",
  obfuscated_script: "লুকানো বা অস্পষ্ট স্ক্রিপ্ট পৃষ্ঠাটি কী করে তা গোপন করে।",
  bad_certificate: "সাইটের TLS সার্টিফিকেট অবৈধ, মেয়াদোত্তীর্ণ বা স্ব-স্বাক্ষরিত।",
  new_domain: "এই ডোমেইনটি খুব সম্প্রতি নিবন্ধিত হয়েছে।",
  qr_risky_payload: "এই পৃষ্ঠার একটি QR কোড ঝুঁকিপূর্ণ URL-এ নিয়ে যায়।",
  unsafe_link: "এই পৃষ্ঠার একটি লিংক অনিরাপদ জায়গায় যায়।",
};

const CATALOGS = { en, hi, bn };

const GENERIC = {
  en: {
    safe: "Nothing suspicious was found.",
    suspicious: "This page shows some warning signs.",
    dangerous: "This page is dangerous. Do not enter passwords or payment details.",
  },
  hi: {
    safe: "कुछ संदिग्ध नहीं मिला।",
    suspicious: "इस पेज में कुछ चेतावनी के संकेत हैं।",
    dangerous: "यह पेज ख़तरनाक है। यहाँ पासवर्ड या भुगतान की जानकारी न डालें।",
  },
  bn: {
    safe: "সন্দেহজনক কিছু পাওয়া যায়নি।",
    suspicious: "এই পৃষ্ঠায় কিছু সতর্কতার লক্ষণ আছে।",
    dangerous: "এই পৃষ্ঠাটি বিপজ্জনক। এখানে পাসওয়ার্ড বা পেমেন্টের তথ্য দেবেন না।",
  },
};

/**
 * Translate a reason code.
 * @param {string} code
 * @param {string} [language]
 * @returns {string} warning sentence (never empty)
 */
export function getAlert(code, language = "en") {
  const lang = CATALOGS[language] ? language : "en";
  const catalog = CATALOGS[lang];
  const key = String(code || "unknown");
  return catalog[key] || en[key] || en.unknown;
}

/**
 * Does this code have copy in this language (rather than an English fallback)?
 * @param {string} code
 * @param {string} [language]
 * @returns {boolean}
 */
export function hasTranslation(code, language = "en") {
  const lang = CATALOGS[language] ? language : "en";
  return Boolean(CATALOGS[lang][String(code || "")]);
}

/**
 * Localise a reason object, falling back to the reason's own text.
 * @param {{code?: string, text?: string, severity?: string}} reason
 * @param {string} [language]
 */
export function alertForReason(reason, language = "en") {
  if (!reason || typeof reason !== "object") return getAlert("unknown", language);
  const code = String(reason.code || "");
  if (code && (hasTranslation(code, language) || hasTranslation(code, "en"))) return getAlert(code, language);
  if (typeof reason.text === "string" && reason.text.trim()) return reason.text;
  return getAlert("unknown", language);
}

/**
 * One sentence for a whole verdict.
 * @param {"safe"|"suspicious"|"dangerous"} verdict
 * @param {string} [language]
 */
export function verdictMessage(verdict, language = "en") {
  const lang = GENERIC[language] ? language : "en";
  return GENERIC[lang][verdict] || GENERIC[lang].suspicious;
}

/**
 * Every code with copy in this language.
 * @param {string} [language]
 * @returns {string[]}
 */
export function listCodes(language = "en") {
  const lang = CATALOGS[language] ? language : "en";
  return Object.keys(CATALOGS[lang]);
}

/** Codes that only have English copy. */
export function missingTranslations(language) {
  const lang = CATALOGS[language] ? language : "en";
  if (lang === "en") return [];
  return Object.keys(en).filter((code) => !CATALOGS[lang][code]);
}

export { SEVERITIES };
