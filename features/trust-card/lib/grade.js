/**
 * Olfa trust-card — grade calculation. Pure, no DOM.
 *
 * Turns a plain input object into a letter grade (A-F) plus per-section grades
 * and one-sentence explanations, the way a nutrition label breaks down a snack.
 *
 * Input (all fields optional; missing ones are treated as "unknown" = C):
 * {
 *   domain, riskScore (0-1, higher = riskier),
 *   domainAgeDays, certificate: {valid, daysToExpiry, selfSigned},
 *   securityHeaders: {grade: 'A'|'B'|'C'|'D'|'F'},
 *   cookies: {total, missingSecure, missingHttpOnly},
 *   reports: {count}
 * }
 */
(function (root) {
  'use strict';

  const POINTS = { A: 4, B: 3, C: 2, D: 1, F: 0 };
  const UNKNOWN = { grade: 'C', points: 2 };

  /** Average points -> letter. */
  function gradeFromPoints(points) {
    if (points >= 3.5) return 'A';
    if (points >= 2.5) return 'B';
    if (points >= 1.5) return 'C';
    if (points >= 0.75) return 'D';
    return 'F';
  }

  function section(key, label, grade, detail, weight) {
    const points = grade in POINTS ? POINTS[grade] : UNKNOWN.points;
    return { key, label, grade, points, detail, weight };
  }

  /** Risk score (0 = harmless, 1 = dangerous) -> grade. */
  function trustSection(riskScore) {
    if (typeof riskScore !== 'number' || Number.isNaN(riskScore)) {
      return section('trust', 'Overall risk', UNKNOWN.grade, 'No scan result for this domain yet.', 0.35);
    }
    const pct = Math.round(riskScore * 100);
    let grade = 'F';
    if (riskScore < 0.1) grade = 'A';
    else if (riskScore < 0.25) grade = 'B';
    else if (riskScore < 0.45) grade = 'C';
    else if (riskScore < 0.75) grade = 'D';
    return section('trust', 'Overall risk', grade, `Olfa rated this domain ${pct}% risky.`, 0.35);
  }

  function ageSection(days) {
    if (typeof days !== 'number' || Number.isNaN(days)) {
      return section('age', 'Domain age', UNKNOWN.grade, 'Registration date unknown.', 0.15);
    }
    let grade = 'A';
    let detail = `Registered ${Math.round(days / 365)}+ years ago.`;
    if (days < 30) {
      grade = 'F';
      detail = `Registered ${Math.round(days)} day(s) ago — brand-new domains are a major phishing signal.`;
    } else if (days < 180) {
      grade = 'D';
      detail = `Registered about ${Math.round(days / 30)} months ago.`;
    } else if (days < 365) {
      grade = 'C';
      detail = 'Registered less than a year ago.';
    } else if (days < 1095) {
      grade = 'B';
      detail = `Registered about ${Math.round(days / 365)} years ago.`;
    }
    return section('age', 'Domain age', grade, detail, 0.15);
  }

  function certificateSection(cert) {
    if (!cert || typeof cert !== 'object') {
      return section('cert', 'Certificate', UNKNOWN.grade, 'No certificate information.', 0.2);
    }
    if (cert.selfSigned === true) {
      return section('cert', 'Certificate', 'F', 'The certificate is self-signed, so nobody vouched for this domain.', 0.2);
    }
    if (cert.valid === false) {
      return section('cert', 'Certificate', 'F', 'The certificate is invalid or expired.', 0.2);
    }
    if (typeof cert.daysToExpiry === 'number' && cert.daysToExpiry < 14) {
      return section('cert', 'Certificate', 'C', `The certificate expires in ${cert.daysToExpiry} day(s).`, 0.2);
    }
    const issuer = cert.issuer ? ` Issued by ${cert.issuer}.` : '';
    return section('cert', 'Certificate', 'A', 'A valid, trusted certificate is in place.' + issuer, 0.2);
  }

  function headersSection(headers) {
    if (!headers || !headers.grade || !(headers.grade in POINTS)) {
      return section('headers', 'Security headers', UNKNOWN.grade, 'Security headers were not checked.', 0.15);
    }
    const missing = Array.isArray(headers.missing) && headers.missing.length ? ` Missing: ${headers.missing.slice(0, 3).join(', ')}.` : '';
    return section('headers', 'Security headers', headers.grade, `Browser hardening grade ${headers.grade}.` + missing, 0.15);
  }

  function cookiesSection(cookies) {
    if (!cookies || typeof cookies !== 'object') {
      return section('cookies', 'Cookie hygiene', UNKNOWN.grade, 'Cookie flags were not checked.', 0.1);
    }
    const total = Number(cookies.total || 0);
    const bad = Number(cookies.missingSecure || 0) + Number(cookies.missingHttpOnly || 0);
    if (!total) return section('cookies', 'Cookie hygiene', 'A', 'No cookies were set.', 0.1);
    const ratio = bad / (total * 2);
    let grade = 'A';
    if (ratio > 0.75) grade = 'F';
    else if (ratio > 0.5) grade = 'D';
    else if (ratio > 0.25) grade = 'C';
    else if (ratio > 0) grade = 'B';
    return section('cookies', 'Cookie hygiene', grade, `${total} cookie(s); ${bad} missing a Secure or HttpOnly flag.`, 0.1);
  }

  function reportsSection(reports) {
    const count = reports && typeof reports.count === 'number' ? reports.count : 0;
    if (count >= 10) return section('reports', 'Community reports', 'F', `${count} people reported this domain.`, 0.05);
    if (count >= 3) return section('reports', 'Community reports', 'D', `${count} reports from other users.`, 0.05);
    if (count >= 1) return section('reports', 'Community reports', 'C', `${count} report so far.`, 0.05);
    return section('reports', 'Community reports', 'A', 'No community reports.', 0.05);
  }

  /** Full card: letter grade + ranked sections + a one-line verdict. */
  function computeGrade(data) {
    const input = data || {};
    const sections = [
      trustSection(input.riskScore),
      certificateSection(input.certificate),
      ageSection(input.domainAgeDays),
      headersSection(input.securityHeaders),
      cookiesSection(input.cookies),
      reportsSection(input.reports),
    ];

    const totalWeight = sections.reduce((sum, s) => sum + s.weight, 0);
    const weighted = sections.reduce((sum, s) => sum + s.points * s.weight, 0) / totalWeight;
    const grade = gradeFromPoints(weighted);

    const verdicts = {
      A: 'Looks trustworthy. Normal care is enough.',
      B: 'Mostly fine, with a few rough edges.',
      C: 'Mixed signals — check before entering anything sensitive.',
      D: 'Several warning signs. Avoid passwords or payments here.',
      F: 'Strong evidence of danger. Do not use this site.',
    };

    const worst = sections
      .filter((s) => s.points <= 1)
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3);

    return {
      domain: input.domain || 'unknown domain',
      grade,
      points: Math.round(weighted * 100) / 100,
      verdict: verdicts[grade],
      sections,
      highlights: worst.map((s) => s.detail),
      generatedAt: new Date().toISOString(),
    };
  }

  const api = { POINTS, gradeFromPoints, computeGrade };
  root.OlfaGrade = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
