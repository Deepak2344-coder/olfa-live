// Scam-text analysis for pasted SMS / email / WhatsApp messages (en, hi, bn).
//
// Replaces features/message-analyzer, whose "HI_RULES"/"BN_RULES" were an
// identity map of the English patterns, so the Hindi and Bengali rules could
// never match Hindi or Bengali script. Here each language gets its own terms.
//
// Runs entirely in the popup: message text is never sent anywhere.

/** weight -> how much one matched rule adds to the risk. */
const WEIGHTS = { high: 0.34, medium: 0.2, low: 0.1 };

/**
 * Rule sets. Each rule: {id, label, severity, pattern}.
 * `label` is the machine tag shown next to the highlighted span.
 */
export const RULES = {
  en: [
    { id: "urgency", label: "urgent language", severity: "medium", pattern: /\b(urgent|immediately|action required|within \d+ hours?|last chance|final notice|expires? today)\b/gi },
    { id: "impersonation", label: "brand impersonation", severity: "medium", pattern: /\b(bank|sbi|hdfc|icici|axis|paypal|amazon|netflix|flipkart|paytm|phonepe|income tax|police|customs)\b/gi },
    { id: "gift_card", label: "gift-card scam", severity: "high", pattern: /\b(gift card|voucher|recharge|top ?up|reload|pin code)\b/gi },
    { id: "credentials", label: "credential harvesting", severity: "high", pattern: /\b(otp|one[- ]time password|pin|password|cvv|net ?banking|login|verify your account|kyc)\b/gi },
    { id: "too_good", label: "too good to be true", severity: "high", pattern: /\b(winner|you have won|lottery|inheritance|prize|clearance fee|cashback|refund)\b/gi },
    { id: "short_link", label: "shortened or raw link", severity: "medium", pattern: /\b(bit\.ly|tinyurl\.com|t\.co|rb\.gy|is\.gd)\b/gi },
  ],
  hi: [
    { id: "urgency", label: "urgent language", severity: "medium", pattern: /(तुरंत|तत्काल|जल्दी करें|आज ही|अंतिम अवसर|खाता बंद)/g },
    { id: "impersonation", label: "brand impersonation", severity: "medium", pattern: /(बैंक|एसबीआई|एचडीएफसी|आईसीआईसीआई|पेपैल|अमेज़न|आयकर विभाग|पुलिस|सीमा शुल्क)/g },
    { id: "gift_card", label: "gift-card scam", severity: "high", pattern: /(गिफ्ट कार्ड|वाउचर|रिचार्ज|पिन कोड)/g },
    { id: "credentials", label: "credential harvesting", severity: "high", pattern: /(ओटीपी|पिन|पासवर्ड|सीवीवी|नेट बैंकिंग|केवाईसी|सत्यापित)/g },
    { id: "too_good", label: "too good to be true", severity: "high", pattern: /(लॉटरी|इनाम|विजेता|रिफंड|कैशबैक|विरासत)/g },
  ],
  bn: [
    { id: "urgency", label: "urgent language", severity: "medium", pattern: /(অবিলম্বে|তাৎক্ষণিক|আজই|শেষ সুযোগ|অ্যাকাউন্ট বন্ধ)/g },
    { id: "impersonation", label: "brand impersonation", severity: "medium", pattern: /(ব্যাংক|এসবিআই|এইচডিএফসি|আইসিআইসিআই|পেপাল|অ্যামাজন|আয়কর|পুলিশ|শুল্ক)/g },
    { id: "gift_card", label: "gift-card scam", severity: "high", pattern: /(গিফট কার্ড|ভাউচার|রিচার্জ|পিন কোড)/g },
    { id: "credentials", label: "credential harvesting", severity: "high", pattern: /(ওটিপি|পিন|পাসওয়ার্ড|সিভিভি|নেট ব্যাংকিং|কেওয়াইসি)/g },
    { id: "too_good", label: "too good to be true", severity: "high", pattern: /(লটারি|পুরস্কার|বিজয়ী|রিফান্ড|ক্যাশব্যাক)/g },
  ],
};

export const LANGUAGES = ["en", "hi", "bn"];
export const MAX_MESSAGE_LENGTH = 4000;

/**
 * Collect every rule hit, deduplicated by position, left to right.
 * @param {string} text
 * @param {string} [language]
 * @returns {Array<{id: string, label: string, severity: string, span: string, start: number, end: number}>}
 */
export function findMatches(text, language = "en") {
  const message = String(text || "").slice(0, MAX_MESSAGE_LENGTH);
  const rules = RULES[language] || RULES.en;
  const found = [];
  const seen = new Set();

  for (const rule of rules) {
    // Fresh regex per call: the patterns carry /g and live at module scope.
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;
    while ((match = pattern.exec(message)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      const key = `${start}:${end}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({ id: rule.id, label: rule.label, severity: rule.severity, span: match[0], start, end });
      }
      if (match[0].length === 0) pattern.lastIndex += 1; // never loop forever
    }
  }

  found.sort((a, b) => a.start - b.start || b.end - a.end);
  return dropOverlaps(found);
}

/** Keep the first hit when two spans overlap. */
function dropOverlaps(matches) {
  const out = [];
  for (const item of matches) {
    const clash = out.some((kept) => item.start < kept.end && item.end > kept.start);
    if (!clash) out.push(item);
  }
  return out;
}

/**
 * Escape text for safe insertion into the popup DOM.
 * @param {string} text
 * @returns {string}
 */
export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Analyse a message.
 * @param {string} text
 * @param {string} [language]
 * @returns {{risk: number, verdict: "safe"|"suspicious"|"dangerous", score: number, matches: Array, highlighted: string, labels: string[]}}
 */
export function analyzeMessage(text, language = "en") {
  const message = String(text || "").slice(0, MAX_MESSAGE_LENGTH);
  const matches = findMatches(message, language);

  let risk = 0;
  const counted = new Set();
  for (const match of matches) {
    // Count each rule once: a message repeating "OTP" five times is not five
    // times more dangerous.
    if (counted.has(match.id)) continue;
    counted.add(match.id);
    risk += WEIGHTS[match.severity] ?? WEIGHTS.medium;
  }
  risk = Math.min(1, Math.round(risk * 10000) / 10000);

  const verdict = risk >= 0.75 ? "dangerous" : risk >= 0.4 ? "suspicious" : "safe";

  return {
    risk,
    verdict,
    score: Math.round((1 - risk) * 100),
    matches,
    labels: Array.from(new Set(matches.map((m) => m.label))),
    highlighted: highlight(message, matches),
  };
}

/**
 * HTML with `<mark>` around each match. All other text is escaped, so pasted
 * markup can never inject anything into the popup.
 * @param {string} message
 * @param {Array} matches
 * @returns {string}
 */
export function highlight(message, matches) {
  let html = "";
  let cursor = 0;
  for (const match of matches) {
    if (match.start < cursor) continue;
    html += escapeHtml(message.slice(cursor, match.start));
    html += `<mark title="${escapeHtml(match.label)}">${escapeHtml(message.slice(match.start, match.end))}</mark>`;
    cursor = match.end;
  }
  html += escapeHtml(message.slice(cursor));
  return html;
}
