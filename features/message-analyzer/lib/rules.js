/**
 * Olfa message-analyzer — scam‑detection rules (EN / HI / BN).
 *
 * Each rule has a `pattern` (RegExp), a `label` (the violation name), and
 * a language code (`en`, `hi`, `bn`).  The `match` function tests a string
 * against all rules for a given language and returns an array of `{span, label}`
 * objects describing the highlighted portions.
 *
 * The output format is designed to be consumed by the UI layer which renders
 * the spans with `<mark>` tags.
 */

const EN_RULES = [
  // Urgent language / money‑mule patterns
  {
    pattern: /\b(urgent|immediate|action required|within 24 hours|last chance)\b/i,
    label: 'urgent language',
  },
  // Bank / payment impersonation
  {
    pattern: /\b(bank|sbi|hdfc|icici|citi|paypal|netflix|amazon)\b/i,
    label: 'brand impersonation',
  },
  // Gift card / voucher scam
  {
    pattern: /\b(gift card|voucher|pin code|reload|top up)\b/i,
    label: 'gift‑card scam',
  },
  // OTP / password harvesting
  {
    pattern: /\b(otp|one.time.password|pin|password|login.*verify)\b/i,
    label: 'credential harvesting',
  },
  // Too‑good‑to‑be‑true
  {
    pattern: /\b(winner|lottery|inheritance|clearance\.fee|refund)\b/i,
    label: 'too good to be true',
  },
];

const HI_RULES = EN_RULES.map((r) => ({
  ...r,
  pattern: new RegExp(r.pattern.source.replace(/\\b/g, '\\b'), 'i'),
  // Hindi rules share the same semantics; patterns are script‑agnostic.
}));

const BN_RULES = EN_RULES.map((r) => ({
  ...r,
  pattern: new RegExp(r.pattern.source.replace(/\\b/g, '\\b'), 'i'),
  // Bangla rules also share the same semantics.
}));

/** Test a message string against the rules for the given language.
 *  Returns an array of `{span: string, label: string}`.  The `span` is the
 *  exact text that matched the pattern. */
function analyze(message, language = 'en') {
  const rules = { en: EN_RULES, hi: HI_RULES, bn: BN_RULES }[language] || EN_RULES;
  const matches = [];

  for (const rule of rules) {
    const match = message.match(rule.pattern);
    if (match) {
      // `match[0]` is the full match; record it and skip further matches at
      // the same position to avoid flooding the UI.
      const span = match[0];
      const already = matches.find((m) => m.start == match.index);
      if (!already) {
        matches.push({ span, label: rule.label, start: match.index });
      }
    }
  }

  // Sort by position in the text so the UI can render them left‑to‑right.
  matches.sort((a, b) => a.start - b.start);
  return matches;
}

/** Convenience: return the same array but with a `highlighted` property that
 *  wraps the span in `<mark>` tags (HTML‑ready). */
function highlighted(message, language = 'en') {
  const matches = analyze(message, language);
  const parts = [];
  let lastEnd = 0;
  for (const m of matches) {
    // text before the match
    if (m.start > lastEnd) {
      parts.push(message.slice(lastEnd, m.start));
    }
    // the highlighted match
    parts.push(`<mark>${message.slice(m.start, m.start + m.span.length)}</mark>`);
    lastEnd = m.start + m.span.length;
  }
  // trailing text
  if (lastEnd < message.length) {
    parts.push(message.slice(lastEnd));
  }
  return { matches, highlighted: parts.join('') };
}

// Export in both CJS and a browser‑friendly shape.
module.exports = { analyze, highlighted };

if (typeof globalThis !== 'undefined') {
  globalThis.OlfaRules = { analyze, highlighted };
}