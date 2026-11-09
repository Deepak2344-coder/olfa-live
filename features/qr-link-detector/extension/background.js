/**
 * Olfa qr-link-detector — background script.
 *
 * Listens for messages from the content script and popup,
 * stores the latest detection results, and provides
 * a persistent store for the popup to read.
 */

const QR_LINK_THRESHOLD = 0.4; // suspicious+ threshold

let latestResults = {
  qrCodes: [],
  redirectLinks: [],
  lastScan: 0,
};

/** Message from content script: new detection results. */
chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    if (message.type === 'qr-link-results') {
      latestResults = {
        qrCodes: message.qrCodes,
        redirectLinks: message.redirectLinks,
        lastScan: Date.now(),
      };
      // Save to storage so popup can read it after page navigation
      chrome.storage.local.set({ qrResults: latestResults });
    }
    sendResponse({ status: 'ok', results: latestResults });
  },
);

/** Helper: get the stored results for the popup. */
chrome.storage.local.get(['qrResults'], (data) => {
  if (data.qrResults) {
    latestResults = data.qrResults;
  }
});