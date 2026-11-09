/**
 * Olfa page-inspector — background worker.
 *
 * Observes (never blocks, never modifies) outgoing requests per tab so the
 * popup can show who a page talks to. Requests live in chrome.storage.session,
 * which survives service-worker restarts and is wiped when the browser closes.
 *
 * Privacy: only the URL, method and resource type are stored — no headers, no
 * bodies, no cookie values.
 */
'use strict';

const MAX_PER_TAB = 400;

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const key = 'req:' + details.tabId;
    chrome.storage.session.get({ [key]: [] }).then((stored) => {
      const list = stored[key];
      // De-duplicate identical method+url pairs; a page can request the same
      // pixel hundreds of times and the popup only needs it once.
      if (list.some((r) => r.url === details.url && r.method === details.method)) return;
      list.push({ url: details.url, method: details.method, type: details.type, at: Date.now() });
      const trimmed = list.slice(-MAX_PER_TAB);
      chrome.storage.session.set({ [key]: trimmed });
    });
  },
  { urls: ['<all_urls>'] }
);

// Starting a fresh navigation clears the previous page's list.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.storage.session.remove('req:' + details.tabId);
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove('req:' + tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'olfa:get-requests') return false;
  const key = 'req:' + message.tabId;
  chrome.storage.session.get({ [key]: [] }).then((stored) => sendResponse({ requests: stored[key] }));
  return true; // async response
});
