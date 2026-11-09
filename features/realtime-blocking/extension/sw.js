/**
 * Olfa realtime-blocking — MV3 service worker.
 *
 * Two layers of defence:
 *   1. rules.json (declarativeNetRequest) hard-blocks the bundled blocklist
 *      before a single byte of the page is fetched.
 *   2. This worker runs the fast local check on onBeforeNavigate, optionally
 *      asks the backend when the local verdict is inconclusive, then either
 *      swaps the tab for the full-screen warning page or asks the content
 *      script to draw the banner.
 *
 * Nothing here is trusted to be perfect: every decision is written to the log
 * page so the user can report false positives.
 */
importScripts('lib/risk-schema.js', 'lib/tier.js');

const DEFAULTS = {
  autoClose: true,
  backendUrl: 'http://127.0.0.1:8790/scan',
  trusted: [],
  log: [],
  blockedOnce: [],
};
const REMOTE_TIMEOUT_MS = 1500;
const POPUP_GESTURE_WINDOW_MS = 1500;

/** Recently opened popup tabs, to decide whether a close is allowed. */
const popups = new Map();

function settings() {
  return chrome.storage.local.get(DEFAULTS).then((stored) => ({ ...DEFAULTS, ...stored }));
}

function warningUrl(result) {
  const params = new URLSearchParams({
    url: result.url,
    score: String(result.score),
    reasons: JSON.stringify(result.reasons.slice(0, 6)),
  });
  return chrome.runtime.getURL('warning.html?' + params.toString());
}

async function addLog(entry) {
  const { log } = await settings();
  const next = [{ at: new Date().toISOString(), ...entry }, ...log].slice(0, 300);
  await chrome.storage.local.set({ log: next });
}

/** Ask the backend only when the local check has nothing to say. */
async function remoteCheck(url) {
  const { backendUrl } = await settings();
  if (!backendUrl) return null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
    const res = await fetch(backendUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url, deep: false }), // quick scan: the 1.5s budget can't fit a full page fetch
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const json = await res.json();
    if (typeof json.score !== 'number') return null;
    return OlfaSchema.makeResult(url, json.score, json.reasons || [], { remote: true });
  } catch (e) {
    return null; // offline is normal; the local verdict stands
  }
}

/** Full decision for one navigation. */
async function decide(url) {
  const { trusted } = await settings();
  const host = OlfaTier.hostOf(url);
  if (trusted.includes(host)) return { tier: 'allow', result: null };

  const local = OlfaTier.localCheck(url);
  if (local.tier !== 'log') return local;

  const remote = await remoteCheck(url);
  if (!remote) return local;
  return { tier: OlfaTier.decideTier(remote.score, {}), result: remote };
}

/**
 * Block a tab: swap it for the warning page, or close it when it is an
 * unattended popup and auto-close is on.
 */
async function blockTab(tab, result) {
  const { autoClose } = await settings();
  const popup = popups.get(tab.id);
  const unattended = popup && popup.openedByPage && !popup.userActivated;

  if (autoClose && unattended) {
    const snapshot = { url: tab.url, windowId: tab.windowId, index: tab.index, title: tab.title || tab.url };
    await chrome.storage.local.set({ lastClosed: snapshot });
    addLog({ kind: 'closed', url: result.url, score: result.score, host: OlfaTier.hostOf(result.url) });
    await chrome.tabs.remove(tab.id);
    chrome.notifications.create('olfa-closed-' + Date.now(), {
      type: 'basic',
      iconUrl: 'assets/hachi.png',
      title: 'Olfa closed a risky tab',
      message: 'Hachi stopped a tab that opened itself: ' + new URL(result.url).hostname,
      buttons: [{ title: 'Undo' }],
      priority: 2,
    });
    return;
  }

  addLog({ kind: 'blocked', url: result.url, score: result.score, host: OlfaTier.hostOf(result.url), reasons: result.reasons.map((r) => r.code) });
  await chrome.tabs.update(tab.id, { url: warningUrl(result) });
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const url = details.url || '';
  if (!/^https?:/i.test(url)) return;
  if (url.startsWith(chrome.runtime.getURL(''))) return;

  decide(url)
    .then(async (decision) => {
      if (decision.tier === 'block') {
        const tab = await chrome.tabs.get(details.tabId).catch(() => null);
        if (tab) await blockTab(tab, decision.result);
        return;
      }
      if (decision.tier === 'warn') {
        addLog({ kind: 'warned', url, score: decision.result.score, host: OlfaTier.hostOf(url) });
        chrome.tabs
          .sendMessage(details.tabId, { type: 'olfa:show-banner', result: decision.result })
          .catch(() => {}); // content script may not be ready yet
      }
    })
    .catch(() => {});
});

/* ------------------------------------------------------------------ */
/* Popup tracking: only tabs a page opened without a user gesture may  */
/* be closed automatically.                                            */
/* ------------------------------------------------------------------ */

chrome.tabs.onCreated.addListener((tab) => {
  if (tab.openerTabId == null) return; // typed by the user: never auto-close
  popups.set(tab.id, {
    openedByPage: true,
    userActivated: false,
    createdAt: Date.now(),
    openerTabId: tab.openerTabId,
  });
  // If the content script has not reported a gesture shortly after load, the
  // tab counts as unattended. navigator.userActivation in the page is the
  // authority; this timer only covers pages where the script never ran.
  setTimeout(() => {
    const entry = popups.get(tab.id);
    if (entry && !entry.userActivated) entry.unattended = true;
  }, POPUP_GESTURE_WINDOW_MS);
});

chrome.tabs.onRemoved.addListener((tabId) => popups.delete(tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab && sender.tab.id;

  if (message && message.type === 'olfa:activation') {
    const entry = popups.get(tabId);
    if (entry) entry.userActivated = Boolean(message.activated);
    sendResponse({ ok: true });
    return true;
  }

  if (message && message.type === 'olfa:trust') {
    settings().then(async ({ trusted }) => {
      const next = Array.from(new Set([...trusted, message.host]));
      await chrome.storage.local.set({ trusted: next });
      sendResponse({ ok: true, trusted: next });
    });
    return true;
  }

  if (message && message.type === 'olfa:report') {
    addLog({ kind: 'false-positive-report', url: message.url, note: message.note || '' }).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message && message.type === 'olfa:get-state') {
    settings().then((st) => sendResponse({ autoClose: st.autoClose, trusted: st.trusted }));
    return true;
  }

  return false;
});

chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  if (buttonIndex !== 0 || !notificationId.startsWith('olfa-closed-')) return;
  const { lastClosed } = await chrome.storage.local.get({ lastClosed: null });
  if (!lastClosed) return;
  // "Undo" reopens the URL, but as a normal tab the user owns: it will not be
  // auto-closed again because it has no opener.
  await chrome.tabs.create({ url: lastClosed.url, windowId: lastClosed.windowId, active: true });
  await chrome.storage.local.remove('lastClosed');
  chrome.notifications.clear(notificationId);
});
