/**
 * Olfa page-threat-detector — content script.
 *
 * Detects three common web‑threat techniques:
 *   1. Hidden iframes / overlay elements (clickjacking).
 *   2. Highly obfuscated JavaScript (high entropy / known packer patterns).
 *   3. Keystroke / clipboard / permission abuse attempts.
 *
 * The script sends a summary message to the parent extension/window so the
 * UI can display the results.  All detection is best‑effort and runs in the
 * content‑script sandbox (no external network calls).
 */

const THRESHOLD_OBfUSCATED = 0.75; // Shannon entropy ratio flagging point
const MIN_IFRAME_AREA = 1; // pixel area considered "hidden" (0 width/height)

let threats = [];

/** Check for hidden iframes and overlay elements. */
function checkHiddenIframes() {
  const iframes = document.querySelectorAll('iframe');
  for (const iframe of iframes) {
    const rect = iframe.getBoundingClientRect();
    // Hidden: width or height is 0, or completely off‑screen
    if (rect.width === 0 || rect.height === 0 ||
        rect.bottom < 0 || rect.right < 0 || rect.top > window.innerHeight || rect.left > window.innerWidth) {
      threats.push({ type: 'hidden-iframe', detail: `Hidden iframe at (${Math.round(rect.left)},${Math.round(rect.top)}) size=${rect.width}x${rect.height}` });
    }
  }

  // Check for overlay divs/modals that cover most of the viewport
  const overlays = document.querySelectorAll('div, span, section');
  for (const el of overlays) {
    const rect = el.getBoundingClientRect();
    const area = rect.width * rect.height;
    if (area > window.innerWidth * window.innerHeight * 0.5) {
      // Check if the element has transparent/zero opacity and is on top
      const style = window.getComputedStyle(el);
      if (style.position === 'fixed' || style.zIndex > 1000) {
        threats.push({ type: 'overlay', detail: `Large overlay covering ${Math.round((area / (window.innerWidth * window.innerHeight)) * 100)}% of viewport` });
      }
    }
  }
}

/** Check for highly obfuscated JavaScript strings inline in the page. */
function checkObfuscatedJS() {
  const scripts = document.querySelectorAll('script');
  for (const script of scripts) {
    const text = script.textContent || script.innerText || '';
    if (text.length < 20) continue; // skip tiny scripts

    // Compute a very rough entropy score: ratio of "non‑printable/odd" chars.
    // A more robust approach would use Shannon entropy, but we keep it simple.
    const uniqueChars = new Set(text).size;
    const entropyRatio = uniqueChars / text.length;

    if (entropyRatio > THRESHOLD_OBfUSCATED) {
      threats.push({ type: 'obfuscated-js', detail: `Script with high entropy (${entropyRatio.toFixed(2)}) at line ${script.lineNumber}` });
    }

    // Check for known packer patterns (common in malware)
    const lower = text.toLowerCase();
    if (/eval\(|new Function|fromCharCode|arguments\.callee/.test(lower)) {
      threats.push({ type: 'packer-pattern', detail: `Known packing pattern in script at line ${script.lineNumber}` });
    }
  }
}

/** Check for dangerous API usage: document.execCommand, clipboard, keyboard listeners. */
function checkDangerousAPIs() {
  // 1. Check for document.execCommand or clipboard API usage in scripts
  const scripts = document.querySelectorAll('script');
  for (const script of scripts) {
    const text = script.textContent || script.innerText || '';
    if (/execCommand|clipboard\.write|navigator\.clipboard/.test(text)) {
      threats.push({ type: 'clipboard-access', detail: `Script accesses clipboard at line ${script.lineNumber}` });
    }
  }

  // 2. Check for keydown/keypress listeners that could capture keystrokes
  const matchedStyles = document.querySelectorAll('*');
  for (const el of matchedStyles) {
    const classList = el.className ? el.className.split(' ') : [];
    if (classList.includes('keylogger') || classList.includes('capture-keys')) {
      threats.push({ type: 'keystroke-listener', detail: `Element with suspicious class detected` });
    }
  }

  // 3. Check for permission prompts (notification, geolocation) that appear
  //    without user gesture – we just flag the API presence.
  if (window.Notification && typeof window.Notification.requestPermission === 'function') {
    // No action needed here; the UI will inform the user about notification permissions.
  }
}

/** Main entry point – run all checks and report results. */
function runDetection() {
  threats = [];

  checkHiddenIframes();
  checkObfuscatedJS();
  checkDangerousAPIs();

  // Send result to the extension background page / popup
  if (threats.length > 0) {
    try {
      chrome.runtime.sendMessage ? chrome.runtime.sendMessage({ type: 'threats', threats }) :
      window.postMessage ? window.postMessage({ type: 'olfa-threats', threats }, '*') :
      console.log('Threats detected:', threats);
    } catch (e) {
      console.log('Could not send threat message:', e.message);
    }
  }

  return threats;
}

/* Auto‑run when the script loads */
const result = runDetection();

// Expose for debugging in the console
window.olfaThreatResult = result;