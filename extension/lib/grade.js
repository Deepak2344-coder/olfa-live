// Letter-grade trust card ("nutrition label").
//
// Ported from features/trust-card/lib/grade.js, with one important change: the
// original expects six hand-built sections (certificate, domain age, headers,
// cookie hygiene, community reports). A browser extension only ever has the
// POST /analyze payload, so `fromResult()` derives those sections from
// `engines[]` + `certificate_chain` and marks genuinely unknown data as C
// instead of inventing a good grade.
import { clampRisk } from "./normalize.js";

const POINTS = { A: 4, B: 3, C: 2, D: 1, F: 0 };
const UNKNOWN_GRADE = "C";

/** Section weights sum to 1. */
export const SECTION_WEIGHTS = {
  trust: 0.35,
  cert: 0.2,
  age: 0.15,
  headers: 0.15,
  cookies: 0.1,
  reports: 0.05,
};

/**
 * Average points -> letter grade.
 * @param {number} points 0-4
 * @returns {"A"|"B"|"C"|"D"|"F"}
 */
export function gradeFromPoints(points) {
  if (points >= 3.5) return "A";
  if (points >= 2.5) return "B";
  if (points >= 1.5) return "C";
  if (points >= 0.75) return "D";
  return "F";
}

/**
 * A 0-1 risk -> letter grade, with the same boundaries as trust-card.
 * @param {number} risk
 * @returns {"A"|"B"|"C"|"D"|"F"}
 */
export function gradeFromRisk(risk) {
  const r = clampRisk(risk);
  if (r < 0.1) return "A";
  if (r < 0.25) return "B";
  if (r < 0.45) return "C";
  if (r < 0.75) return "D";
  return "F";
}

function section(key, label, grade, detail) {
  return { key, label, grade, points: POINTS[grade] ?? POINTS[UNKNOWN_GRADE], detail, weight: SECTION_WEIGHTS[key] };
}

/**
 * Build the card from already-derived section inputs.
 * @param {object} input {domain, risk, certificate, domainAgeDays, securityHeaders, cookies, reports}
 */
export function computeGrade(input) {
  const data = input && typeof input === "object" ? input : {};
  // An absent risk means "unknown", which must not grade as an A.
  const riskKnown = data.risk !== undefined && data.risk !== null && Number.isFinite(Number(data.risk));
  const risk = riskKnown ? clampRisk(data.risk) : 0;

  const sections = [
    section(
      "trust",
      "Overall risk",
      riskKnown ? gradeFromRisk(risk) : UNKNOWN_GRADE,
      riskKnown ? `Rated ${Math.round(risk * 100)}% risky.` : "No scan result for this domain yet."
    ),
  ];

  /* certificate */
  const cert = data.certificate;
  if (!cert || typeof cert !== "object") {
    sections.push(section("cert", "Certificate", UNKNOWN_GRADE, "No certificate information."));
  } else if (cert.selfSigned === true) {
    sections.push(section("cert", "Certificate", "F", "The certificate is self-signed, so nobody vouched for this domain."));
  } else if (cert.valid === false) {
    sections.push(section("cert", "Certificate", "F", "The certificate is invalid or expired."));
  } else if (typeof cert.daysToExpiry === "number" && cert.daysToExpiry < 14) {
    sections.push(section("cert", "Certificate", "C", `The certificate expires in ${cert.daysToExpiry} day(s).`));
  } else {
    const issuer = cert.issuer ? ` Issued by ${cert.issuer}.` : "";
    sections.push(section("cert", "Certificate", "A", `A valid, trusted certificate is in place.${issuer}`));
  }

  /* domain age */
  const days = Number(data.domainAgeDays);
  if (!Number.isFinite(days)) {
    sections.push(section("age", "Domain age", UNKNOWN_GRADE, "Registration date unknown."));
  } else if (days < 30) {
    sections.push(section("age", "Domain age", "F", `Registered ${Math.max(0, Math.round(days))} day(s) ago — brand-new domains are a major phishing signal.`));
  } else if (days < 180) {
    sections.push(section("age", "Domain age", "D", `Registered about ${Math.round(days / 30)} month(s) ago.`));
  } else if (days < 365) {
    sections.push(section("age", "Domain age", "C", "Registered less than a year ago."));
  } else if (days < 1095) {
    sections.push(section("age", "Domain age", "B", `Registered about ${Math.round(days / 365)} year(s) ago.`));
  } else {
    sections.push(section("age", "Domain age", "A", `Registered ${Math.round(days / 365)}+ years ago.`));
  }

  /* security headers */
  const headers = data.securityHeaders;
  if (!headers || !headers.grade || !(headers.grade in POINTS)) {
    sections.push(section("headers", "Security headers", UNKNOWN_GRADE, "Security headers were not checked."));
  } else {
    const missing = Array.isArray(headers.missing) && headers.missing.length ? ` Missing: ${headers.missing.slice(0, 3).join(", ")}.` : "";
    sections.push(section("headers", "Security headers", headers.grade, `Browser hardening grade ${headers.grade}.${missing}`));
  }

  /* cookies */
  const cookies = data.cookies;
  if (!cookies || typeof cookies !== "object") {
    sections.push(section("cookies", "Cookie hygiene", UNKNOWN_GRADE, "Cookie flags were not checked."));
  } else {
    const total = Number(cookies.total || 0);
    const bad = Number(cookies.missingSecure || 0) + Number(cookies.missingHttpOnly || 0);
    if (!total) {
      sections.push(section("cookies", "Cookie hygiene", "A", "No cookies were set."));
    } else {
      const ratio = bad / (total * 2);
      let grade = "A";
      if (ratio > 0.75) grade = "F";
      else if (ratio > 0.5) grade = "D";
      else if (ratio > 0.25) grade = "C";
      else if (ratio > 0) grade = "B";
      sections.push(section("cookies", "Cookie hygiene", grade, `${total} cookie(s); ${bad} missing a Secure or HttpOnly flag.`));
    }
  }

  /* community reports */
  const count = data.reports && Number.isFinite(Number(data.reports.count)) ? Number(data.reports.count) : 0;
  if (count >= 10) sections.push(section("reports", "Community reports", "F", `${count} people reported this domain.`));
  else if (count >= 3) sections.push(section("reports", "Community reports", "D", `${count} reports from other users.`));
  else if (count >= 1) sections.push(section("reports", "Community reports", "C", `${count} report so far.`));
  else sections.push(section("reports", "Community reports", "A", "No community reports."));

  const totalWeight = sections.reduce((sum, s) => sum + s.weight, 0) || 1;
  const weighted = sections.reduce((sum, s) => sum + s.points * s.weight, 0) / totalWeight;
  const grade = gradeFromPoints(weighted);

  const verdicts = {
    A: "Looks trustworthy. Normal care is enough.",
    B: "Mostly fine, with a few rough edges.",
    C: "Mixed signals — check before entering anything sensitive.",
    D: "Several warning signs. Avoid passwords or payments here.",
    F: "Strong evidence of danger. Do not use this site.",
  };

  const highlights = sections
    .filter((s) => s.points <= 1)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => s.detail);

  return {
    domain: data.domain || "unknown domain",
    grade,
    points: Math.round(weighted * 100) / 100,
    verdict: verdicts[grade],
    sections,
    highlights,
  };
}

/**
 * Derive a card from a POST /analyze payload plus whatever page facts we have.
 *
 * Engine risks are 0-1 where higher = riskier, so they map straight onto the
 * section inputs: `transport` covers headers/HSTS, `certificate_chain` covers
 * the certificate, `reputation` stands in for report counts.
 *
 * @param {object} result raw /analyze response
 * @param {object} [facts] page facts from lib/signals.js (cookies/signals)
 */
export function fromResult(result, facts) {
  const payload = result && typeof result === "object" ? result : {};
  const engines = Array.isArray(payload.engines) ? payload.engines : [];
  const engineRisk = (name) => {
    const engine = engines.find((e) => e && e.name === name);
    return engine && Number.isFinite(Number(engine.risk)) ? clampRisk(engine.risk) : null;
  };

  const certRisk = engineRisk("certificate_chain");
  const transportRisk = engineRisk("transport");
  const reputationRisk = engineRisk("reputation");

  let domain = "";
  try {
    domain = new URL(payload.url).hostname;
  } catch {
    domain = String(payload.url || "");
  }

  const chain = Array.isArray(payload.certificate_chain) ? payload.certificate_chain : [];
  const leaf = chain.find((entry) => entry && entry.role === "leaf") || chain[chain.length - 1];
  let certificate;
  if (certRisk !== null || leaf) {
    certificate = {
      valid: certRisk === null ? true : certRisk < 0.5,
      selfSigned: Boolean(leaf && /self|unknown/i.test(String(leaf.status || ""))) && Boolean(certRisk && certRisk > 0.5),
      issuer: leaf && leaf.issuer ? String(leaf.issuer) : "",
    };
  }

  const securityHeaders = transportRisk === null
    ? undefined
    : { grade: transportRisk < 0.2 ? "A" : transportRisk < 0.4 ? "B" : transportRisk < 0.6 ? "C" : transportRisk < 0.8 ? "D" : "F" };

  const signals = (facts && facts.signals) || {};
  const collected = (facts && facts.collected) || {};
  const cookies = collected.cookies === undefined
    ? undefined
    : {
        total: Number(collected.cookies) || 0,
        missingSecure: Number(signals.cookies_missing_secure) || 0,
        missingHttpOnly: 0,
      };

  return computeGrade({
    domain,
    // A missing score stays unknown instead of being read as "score 0".
    risk: Number.isFinite(Number(payload.score)) ? clampRisk(1 - Number(payload.score) / 100) : undefined,
    certificate,
    securityHeaders,
    cookies,
    reports: reputationRisk === null ? undefined : { count: reputationRisk > 0.7 ? 10 : reputationRisk > 0.4 ? 3 : 0 },
  });
}
