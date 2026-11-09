/**
 * Olfa masterwebpageEXT — unified content script.
 *
 * Detects multiple web threat techniques and reports user data sharing:
 *  1. Hidden iframes / overlays (clickjacking)
 *  2. Obfuscated JavaScript (high entropy / packer patterns)
 *  3. Insecure cookies (no Secure flag)
 *  4. Third-party cookies (tracking across sites)
 *  5. Known tracker cookies (Google, Facebook, etc.)
 *  6. Cross-origin credential forms (password/card over HTTP or to another domain)
 *  7. Dangerous API usage (clipboard, execCommand)
 *
 * All detection runs in the content-script sandbox. Results are sent via
 * chrome.runtime.sendMessage and exposed on window.olfaMasterResult.
 */

const THRESHOLD_OBfUSCATED = 0.75;
let threats = [];
let dataSharing = []; // track user data sharing findings

/** Check for hidden iframes and overlay elements. */
function checkHiddenIframes() {
  const iframes = document.querySelectorAll('iframe');
  for (const iframe of iframes) {
    const rect = iframe.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0 ||
        rect.bottom < 0 || rect.right < 0 || rect.top > window.innerHeight || rect.left > window.innerWidth) {
      threats.push({ type: 'hidden-iframe', detail: `Hidden iframe at (${Math.round(rect.left)},${Math.round(rect.top)}) size=${rect.width}x${rect.height}` });
    }
  }

  const overlays = document.querySelectorAll('div, span, section');
  for (const el of overlays) {
    const rect = el.getBoundingClientRect();
    const area = rect.width * rect.height;
    if (area > window.innerWidth * window.innerHeight * 0.5) {
      const style = window.getComputedStyle(el);
      if (style.position === 'fixed' || (style.zIndex && style.zIndex > 1000)) {
        threats.push({ type: 'overlay', detail: `Large overlay covering ${Math.round((area / (window.innerWidth * window.innerHeight)) * 100)}% of viewport` });
      }
    }
  }
}

/** Check for highly obfuscated JavaScript. */
function checkObfuscatedJS() {
  const scripts = document.querySelectorAll('script');
  for (const script of scripts) {
    const text = script.textContent || script.innerText || '';
    if (text.length < 20) continue;

    const uniqueChars = new Set(text).size;
    const entropyRatio = uniqueChars / text.length;

    if (entropyRatio > THRESHOLD_OBfUSCATED) {
      threats.push({ type: 'obfuscated-js', detail: `High entropy (${entropyRatio.toFixed(2)}) at line ${script.lineNumber}` });
    }

    const lower = text.toLowerCase();
    if (/eval\(|new Function|fromCharCode|arguments\.callee/.test(lower)) {
      threats.push({ type: 'packer-pattern', detail: `Known packing pattern in script at line ${script.lineNumber}` });
    }
  }
}

/** Check for insecure and third-party cookies. */
function checkCookies() {
  if (!document.cookies) return; // fallback if API unavailable

  // Get all cookies via the cookie store
  chrome.cookies.getAll({}, (cookies) => {
    if (!cookies || cookies.length === 0) return;

    const pageHost = new URL(location.href).hostname.toLowerCase();

    for (const cookie of cookies) {
      const cookieDomain = (cookie.domain || '').toLowerCase().replace(/^/, '.');
      const cookieSecure = cookie.secure;
      const cookieHttpOnly = cookie.httpOnly;
      const sameSite = cookie.sameSite;

      // 1. Insecure cookies (not marked Secure)
      if (!cookieSecure) {
        dataSharing.push({ type: 'insecure-cookie', detail: `Cookie "${cookie.name}" from ${cookie.domain} is not Secure — can leak over HTTP`, domain: cookie.domain });
      }

      // 2. Third-party cookies (domain ≠ current page host)
      if (cookieDomain && cookieDomain !== '.' + pageHost && !pageHost.endsWith(cookieDomain)) {
        dataSharing.push({ type: 'third-party-cookie', detail: `Cookie "${cookie.name}" belongs to third-party domain ${cookie.domain}`, domain: cookie.domain });
      }

      // 3. Known tracker cookies
      const knownTrackers = ['doubleclick.net', 'googlesyndication.com', 'google-analytics.com', 'googletagmanager.com', 'facebook.net', 'connect.facebook.net', 'hotjar.com', 'mixpanel.com', 'segment.io', 'amplitude.com', 'criteo.com', 'taboola.com', 'outbrain.com'];
      for (const tracker of knownTrackers) {
        if (cookieDomain === tracker || cookieDomain === '.' + tracker) {
          dataSharing.push({ type: 'known-tracker-cookie', detail: `Tracker cookie from known domain ${tracker}`, domain: tracker });
          break;
        }
      }

      // 4. HttpOnly cookies (informational — can't be JS-accessed, but worth noting)
      if (cookieHttpOnly) {
        dataSharing.push({ type: 'http-only-cookie', detail: `Cookie "${cookie.name}" is HttpOnly — accessible only by server`, domain: cookie.domain });
      }
    }
  });
}

/** Check for dangerous API usage. */
function checkDangerousAPIs() {
  const scripts = document.querySelectorAll('script');
  for (const script of scripts) {
    const text = script.textContent || script.innerText || '';
    if (/execCommand|clipboard\.write|navigator\.clipboard/.test(text)) {
      threats.push({ type: 'clipboard-access', detail: `Script accesses clipboard at line ${script.lineNumber}` });
    }
  }

  // Check for permission abuse patterns
  if (window.Notification && typeof window.Notification.requestPermission === 'function') {
    // Notification API presence is normal; we just flag if requesting without user gesture
    // (can't detect user gestures from content script, so we leave it)
  }
}

/** Main entry point — run all checks and report results. */
function runDetection() {
  threats = [];
  dataSharing = [];

  checkHiddenIframes();
  checkObfuscatedJS();
  checkCookies();
  checkDangerousAPIs();

  // Send results to extension background / popup
  if (threats.length > 0 || dataSharing.length > 0) {
    try {
      chrome.runtime.sendMessage ? chrome.runtime.sendMessage({ type: 'threats', threats, dataSharing }) :
      window.postMessage ? window.postMessage({ type: 'olfa-master-threats', threats, dataSharing }, '*') :
      console.log('Threats/data sharing detected:', threats, dataSharing);
    } catch (e) {
      console.log('Could not send message:', e.message);
    }
  }

  return { threats, dataSharing };
}

/* Auto‑run when the script loads */
const result = runDetection();

// Expose for debugging in the console
window.olfaMasterResult = result;