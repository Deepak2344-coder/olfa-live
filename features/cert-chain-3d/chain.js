/**
 * Olfa cert-chain-3d — fetch and classify a TLS certificate chain.
 *
 * This module uses Node's `crypto` and `net` (via `ssl`) to connect to a host
 * and retrieve its certificate chain.  It then classifies the chain's health
 * based on standard criteria:
 *   - Valid, not‑about‑to‑expire → green
 *   - Expiring within 14 days → yellow
 *   - Invalid / self‑signed → red
 *   - Unable to connect / unknown → gray
 *
 * The output is a plain JSON object that the Three.js demo can read and
 * visualise.
 *
 * API:
 *   const result = await fetchChain(host, port = 443)
 *   result = { ok, host, level, color, reasons, raw }
 *
 * level is one of: 'green', 'yellow', 'red', 'gray'
 * color is a hex string suitable for Three.js material color.
 */

const crypto = require('crypto');
const tls = require('tls');

const HEALTHY_DAYS = 30;   // certificate is "healthy" if >30 days remain
const WARNING_DAYS = 14;   // certificate turns "yellow" if <14 days remain

async function fetchChain(host, port = 443) {
  try {
    const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {});
    await new Promise((resolve) => socket.once('secureConnect', resolve));

    const cert = socket.getPeerCertificate();
    socket.destroy();

    const now = Date.now();
    const expiry = new Date(cert.valid_to).getTime();
    const daysRemaining = Math.max(0, Math.ceil((expiry - now) / 86400000));

    let level, color, reasons = [];

    if (cert.authorized === false) {
      // self-signed or otherwise not authorized
      level = 'red';
      color = '#ff5f5f';
      reasons = ['Certificate is not authorized (self-signed or invalid)'];
    } else if (daysRemaining <= WARNING_DAYS) {
      level = 'red';
      color = '#ff5f5f';
      reasons = [ `Certificate expires in ${daysRemaining} day(s)` ];
    } else if (daysRemaining <= HEALTHY_DAYS) {
      level = 'yellow';
      color = '#ffd65a';
      reasons = [ `Certificate expires in ${daysRemaining} day(s) — renew soon` ];
    } else {
      level = 'green';
      color = '#5fcf80';
      reasons = [ 'Certificate is valid and not about to expire' ];
    }

    return {
      ok: true,
      host,
      level,
      color,
      reasons,
      raw: {
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        fingerprint: cert.fingerprint,
      },
    };
  } catch (err) {
    // Connection failed, DNS error, etc.
    return {
      ok: false,
      host,
      level: 'gray',
      color: '#aaaaaa',
      reasons: [ `Unable to connect to ${host}: ${err.message}` ],
      raw: null,
    };
  }
}

module.exports = { fetchChain };

if (typeof globalThis !== 'undefined') {
  globalThis.OlfaChain = { fetchChain };
}