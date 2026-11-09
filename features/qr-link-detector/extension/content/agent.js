/**
 * Olfa qr-link-detector — content script.
 *
 * Scans the current page for:
 *   1. QR codes (using a lightweight jsQR shim)
 *   2. Redirect / shortened links (bit.ly, tinyurl, t.co, etc.)
 *
 * Sends results to the background script so the popup can display them.
 *
 * All detection runs in the content-script sandbox. No external network calls.
 */

const SHORTENER_DOMAINS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'short.link',
  'is.gd',
  'buff.ly',
  'rebrandly.com',
  'bit.do',
];

const SUSPICIOUS_TRAILING_PARAMETERS = [
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'gclid',
  'fbclid',
  'mc_campaign',
  'mc_id',
];

/** Heuristic: estimate if an image element or canvas might contain a QR code.
 *  In a production extension, this would use the real jsQR library.
 *  Here we use a simple heuristic: look for <img> elements with QR-related
 *  attributes, or canvas elements that might have been drawn from a camera feed.
 *  The popup UI will indicate when a QR code is "possibly detected" versus
 *  confirmed (real jsQR would be needed for confirmation).
 */

function mightContainQR(node) {
  const tag = node.tagName.toLowerCase();
  if (tag === 'img') {
    const src = node.getAttribute('src') || '';
    const width = node.getAttribute('width') || '';
    const height = node.getAttribute('height') || '';
    // Simple heuristics: reasonably sized image, possibly a QR code
    const w = parseInt(width, 10) || 0;
    const h = parseInt(height, 10) || 0;
    // QR codes are typically square and have a minimum size
    if (w >= 20 && h >= 20 && w <= 1000 && h <= 1000) {
      // Check if src looks like it could contain a QR (image URL, not a tracking pixel)
      if (src && src.length > 10 && !src.match(/\.(png|jpe?g|gif|svg)(\?|$)/i)) {
        // It's an image, might be a QR code
        return { tag: 'img', selector: node.selector || 'img', src };
      }
    }
  }
  if (tag === 'canvas') {
    return { tag: 'canvas', selector: node selector || 'canvas' };
  }
  // Check for elements with QR-related classes or IDs
  const classList = node.className ? node.className.split(' ') : [];
  if (classList.some(c => c.toLowerCase().includes('qr') || c.toLowerCase().includes('code'))) {
    return { tag: 'element', selector: node.selector || node.tagName, classes: classList };
  }
  return null;
}

/** Scan the page for potential QR code containers. */
function scanPageForQR() {
  const candidates = [];
  const allNodes = document.querySelectorAll('img, canvas');

  for (const node of allNodes) {
    const result = mightContainQR(node);
    if (result) {
      candidates.push(result);
    }
  }

  // Also check for <svg> elements that might be QR codes
  const svgs = document.querySelectorAll('svg');
  for (const svg of svgs) {
    // Simple: if SVG has a path that looks like it could encode data
    const innerHTML = svg.innerHTML || '';
    if (innerHTML && innerHTML.length > 50 && innerHTML.length < 2000) {
      candidates.push({ tag: 'svg', selector: svg.selector || 'svg', innerHTML: innerHTML.slice(0, 200) });
    }
  }

  return candidates;
}

/** Detect shortened/redirect links on the page. */
function scanPageForRedirects() {
  const links = document.querySelectorAll('a[href]');
  const findings = [];

  for (const link of links) {
    const href = link.getAttribute('href') || '';
    if (!href) continue;

    try {
      const url = new URL(href, location.href);
      const hostname = url.hostname.toLowerCase();

      // Check against known shorteners
      const isShortener = SHORTENER_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));

      if (isShortener) {
        findings.push({
          type: 'redirect-link',
          url: href,
          displayUrl: shortenDisplayUrl(href),
          domain: hostname,
          element: link,
          severity: 'medium',
        });
        continue;
      }

      // Check for trailing suspicious parameters (UTM, gclid, fbclid, etc.)
      const urlParams = new URLSearchParams(url.search);
      const suspiciousParams = [];
      for (const [key] of urlParams) {
        const lowerKey = key.toLowerCase();
        if (SUSPICIOUS_TRAILING_PARAMETERS.includes(lowerKey)) {
          suspiciousParams.push(key);
        }
      }

      if (suspiciousParams.length > 0) {
        findings.push({
          type: 'tracked-link',
          url: href,
          displayUrl: shortenDisplayUrl(href),
          domain: hostname,
          element: link,
          suspiciousParams: suspiciousParams,
          severity: 'low',
        });
      }
    } catch (e) {
      // Malformed URL, skip
    }
  }

  return findings;
}

/** Shorten a display URL for UI (show first 30 chars + ...) */
function shortenDisplayUrl(url) {
  if (url.length <= 30) return url;
  return url.slice(0, 30) + '…';
}

/** Main entry point: scan page and send results to background. */
function runScan() {
  const qrCandidates = scanPageForQR();
  const redirectFindings = scanPageForRedirects();

  // Build QR code results (marked as "possible" since we're not using full jsQR)
  const qrCodes = qrCandidates.map((candidate) => ({
    type: 'qr-code',
    description: `Possible QR code (${candidate.tag}): ${candidate.src || candidate.innerHTML || 'image element'}`,
    source: candidate.src || candidate.innerHTML || 'canvas',
    severity: 'low',
    raw: candidate,
  }));

  const results = {
    qrCodes: qrCodes,
    redirectLinks: redirectFindings,
    scanTimestamp: Date.now(),
  };

  // Send to background script
  try {
    chrome.runtime.sendMessage
      ? chrome.runtime.sendMessage({ type: 'qr-link-results', results })
      : chrome.runtime.sendMessage({ type: 'qr-link-results', results });
  } catch (e) {
    console.log('Failed to send QR-link results:', e.message);
  }

  // Also expose via window for debugging
  window.olfaQrLinkResult = results;

  return results;
}

/* Auto‑run when the script loads */
const scanResults = runScan();

// Also run on DOM mutations (simple observer for SPA-like behavior)
if (window.MutationObserver) {
  const observer = new MutationObserver(() => {
    // Debounce: only scan every 5 seconds
    let timeoutId;
    observer.disconnect();
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      runScan();
      observer.observe(document.body, { childList: true, subtree: true });
    }, 5000);
  });
  observer.observe(document.body, { childList: true, subtree: true });
}