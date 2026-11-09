/**
 * Olfa page-threat-detector — inspector helper (Node / standalone).
 *
 * This module mimics the detection logic of the content script so that the
 * feature can be tested outside the browser.  It exports the same three
 * check functions and a runDetection entry point.
 */

const THRESHOLD_OBfUSCATED = 0.75;

function checkHiddenIframes() {
  // In Node there is no DOM, so we return an empty array.
  // In a browser this would query the DOM as in the content script.
  return [];
}

function checkObfuscatedJS(text = '') {
  if (text.length < 20) return [];
  const uniqueChars = new Set(text).size;
  const entropyRatio = uniqueChars / text.length;
  const results = [];
  if (entropyRatio > THRESHOLD_OBfUSCATED) {
    results.push({ type: 'obfuscated-js', detail: `High entropy (${entropyRatio.toFixed(2)})` });
  }
  const lower = text.toLowerCase();
  if (/eval\(|new Function|fromCharCode|arguments\.callee/.test(lower)) {
    results.push({ type: 'packer-pattern', detail: 'Known packing pattern' });
  }
  return results;
}

function checkDangerousAPIs(text = '') {
  const results = [];
  if (/execCommand|clipboard\.write|navigator\.clipboard/.test(text)) {
    results.push({ type: 'clipboard-access', detail: 'Clipboard API usage' });
  }
  return results;
}

function runDetection(text = '') {
  const threats = [];
  threats.push(...checkHiddenIframes());
  threats.push(...checkObfuscatedJS(text));
  threats.push(...checkDangerousAPIs(text));
  return threats;
}

module.exports = { checkHiddenIframes, checkObfuscatedJS, checkDangerousAPIs, runDetection };