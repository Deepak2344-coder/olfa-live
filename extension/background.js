// Olfa Master Extension - Background Service Worker (MV3, ES module).
// Realtime threat interception, offline triage, ML analysis, QR quishing detection,
// and ad/popup blocker protection.
import { getSettings, analyze, analyzeMany, clearUrlCache, LINK_CHECK_LIMIT } from "./lib/api.js";
import { badgeFor, isHttpUrl } from "./lib/logic.js";
import { localCheck, hostOf } from "./lib/triage.js";
import { combine, fromScan, fromAnalyze, verdictFromRisk } from "./lib/normalize.js";
import { analyzeSignals, emptyFacts } from "./lib/signals.js";
import { scanThreats } from "./lib/threats.js";
import { fromResult } from "./lib/grade.js";
import { toHttpUrl, qrTextToUrl, highlightClass, reasonText, summarizeLinks } from "./lib/qr.js";
import { isPopupAdUrl } from "./lib/adblock.js";

/** Per-tab scan state (memory only; fallback in storage). */
const tabState = new Map();
const allowedOnce = new Set();
const popupsCreated = new Map(); // tabId -> { openedAt, openerTabId, url }

const MAX_TARGETS = 200;
/** Only these in-page findings are strong enough to raise the verdict on their own. */
const HARD_PAGE_CODES = new Set(["credential_form_cross_origin", "keystroke_exfiltration"]);
const PAGE_ADVISORY_MAX = 0.35;
const COOKIE_MAX = 60;

/* ---------- badge helpers ---------- */

function paintBadge(tabId, state) {
  const badge = badgeFor(state);
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  chrome.action.setBadgeText({ tabId, text: badge.text });
  chrome.action.setTitle({ tabId, title: badge.tooltip });
  // let the floating mascot on the page react to the new verdict
  chrome.tabs.sendMessage(tabId, { type: "olfa:verdict", ...verdictPayload(tabId, state) }).catch(() => {});
}

function verdictPayload(tabId, state) {
  const st = state || tabState.get(tabId);
  if (st && (st.kind === "off" || st.kind === "error")) return { kind: st.kind };
  if (!st || st.kind === "scanning") return { kind: "scanning" };
  const unified = tabState.get(tabId)?.unified;
  const verdict = st.verdict || unified?.verdict;
  if (!verdict) return { kind: "scanning" };
  const top = unified?.reasons?.[0];
  return {
    kind: "done", verdict,
    reason: (top && (top.text || top.message)) || "",
    score: Math.round(Number(unified?.score ?? st.score ?? 0)),
    reasons: (unified?.reasons || []).slice(0, 3).map((r) => ({ text: r.text || r.message || "", severity: r.severity || "medium" })),
  };
}

/* ---------- page data & threat fusion ---------- */

async function refreshDerived(state, settings) {
  const facts = { ...emptyFacts(), ...(state.facts || {}) };
  const pageSignals = analyzeSignals(facts);
  state.pageSignals = pageSignals;

  const threats = scanThreats(state.threats || {});
  state.threats = { ...(state.threats || {}), ...threats };

  if (settings.inspectPage) {
    state.cookies = await readCookies(state.url);
  }

  // URL-level verdict (local + backend) is kept separately so page signals never
  // compound on repeated refreshes and can never override it downward or upward unfairly.
  if (!state.urlUnified) state.urlUnified = state.unified || { url: state.url, risk: 0, score: 100, reasons: [], sources: ["local"] };
  const base = state.urlUnified;

  // Page behaviour (hidden iframes, overlays, trackers, fingerprinting, API use) also
  // appears on ordinary sites, so it is ADVISORY: capped below the "dangerous" line
  // (and below the 0.4 "suspicious" line) unless it contains hard evidence.
  const pageReasons = [...pageSignals.reasons, ...threats.reasons];
  const hard = pageReasons.some((r) => HARD_PAGE_CODES.has(r.code));
  const pageRisk = Math.max(pageSignals.risk, threats.risk);
  const effectivePage = hard ? pageRisk : Math.min(pageRisk, PAGE_ADVISORY_MAX);

  const combinedRisk = Math.max(base.risk || 0, effectivePage);
  state.unified = {
    ...base,
    risk: combinedRisk,
    verdict: verdictFromRisk(combinedRisk),
    score: Math.round((1 - combinedRisk) * 100),
    pageHard: hard,
    reasons: dedupeReasons([
      ...(base.reasons || []),
      ...pageReasons.map((r) => (hard || r.severity === "low" ? r : { ...r, severity: r.severity === "high" ? "medium" : r.severity })),
    ]),
  };

  state.grade = fromResult(state.result || null, {
    signals: pageSignals.signals,
    collected: { ...pageSignals.collected, ...(state.cookies && state.cookies.total !== undefined ? { cookies: state.cookies.total } : {}) },
  });
}

function dedupeReasons(reasons) {
  const seen = new Set();
  const out = [];
  for (const item of reasons) {
    if (!item || !item.text) continue;
    const key = `${item.code}|${item.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  const order = { high: 0, medium: 1, low: 2 };
  out.sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
  return out.slice(0, 15);
}

async function readCookies(url) {
  try {
    if (!chrome.cookies || !chrome.permissions) return null;
    const granted = await chrome.permissions.contains({ permissions: ["cookies"], origins: ["<all_urls>"] });
    if (!granted) return null;
    const list = await chrome.cookies.getAll({ url });
    const cookies = list.slice(0, COOKIE_MAX).map((c) => ({
      name: String(c.name || "").slice(0, 40),
      domain: String(c.domain || ""),
      secure: Boolean(c.secure),
      httpOnly: Boolean(c.httpOnly),
      sameSite: String(c.sameSite || ""),
      expires: Number(c.expirationDate) || 0,
    }));
    return {
      total: cookies.length,
      missingSecure: cookies.filter((c) => !c.secure).length,
      missingHttpOnly: cookies.filter((c) => !c.httpOnly).length,
      list: cookies.slice(0, 20),
    };
  } catch {
    return null;
  }
}

/* ---------- real-time navigation interceptor ---------- */

async function isTrustedHost(host) {
  try {
    const { trustedDomains } = await chrome.storage.local.get({ trustedDomains: [] });
    return Array.isArray(trustedDomains) && trustedDomains.includes(host);
  } catch {
    return false;
  }
}

function buildWarningUrl(url, score, reasons, tier = "block") {
  const params = new URLSearchParams({
    url,
    score: String(score),
    reasons: JSON.stringify(reasons.slice(0, 6)),
    tier,
  });
  return chrome.runtime.getURL(`warning.html?${params.toString()}`);
}

// Early navigation check to intercept dangerous sites before page renders
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // Main frame only
    const url = details.url;
    if (!isHttpUrl(url)) return;

    const host = hostOf(url);
    if (!host) return;
    if (allowedOnce.has(host) || (await isTrustedHost(host))) return;

    const settings = await getSettings();
    if (!settings.enabled || !settings.realtimeBlock) return;

    const local = localCheck(url);
    if (local.blocklisted || local.risk >= 0.75) {
      chrome.tabs.update(details.tabId, {
        url: buildWarningUrl(url, local.risk, local.reasons, "block"),
      });
    }
  });
}

/* ---------- pop-up ad blocker ---------- */

chrome.tabs.onCreated.addListener(async (tab) => {
  const settings = await getSettings();
  if (!settings.enabled || !settings.blockPopups) return;

  const url = tab.url || tab.pendingUrl || "";
  const tabId = tab.id;
  const openerTabId = tab.openerTabId;

  if (openerTabId) {
    popupsCreated.set(tabId, { openedAt: Date.now(), openerTabId, url });
  }

  // If newly created tab matches known popup ad networks, close immediately
  if (url && isPopupAdUrl(url)) {
    try {
      await chrome.tabs.remove(tabId);
      recordBlockedPopup(url);
    } catch {
      // tab might already be gone
    }
  }
});

async function recordBlockedPopup(url) {
  try {
    const { blockedPopupsCount } = await chrome.storage.local.get({ blockedPopupsCount: 0 });
    await chrome.storage.local.set({ blockedPopupsCount: blockedPopupsCount + 1 });
  } catch {
    // ignore
  }
}

/* ---------- scan pipeline ---------- */

async function scanTab(tabId, url, settings) {
  const local = localCheck(url);
  const previous = tabState.get(tabId);
  tabState.set(tabId, { url, kind: "scanning", local, unified: combine(local, null) });
  paintBadge(tabId, { kind: "done", verdict: local.verdict, score: local.score });

  const state = {
    url,
    kind: "scanning",
    local,
    unified: combine(local, null),
    facts: previous && previous.url === url ? previous.facts : undefined,
    threats: previous && previous.url === url ? previous.threats : undefined,
    links: previous && previous.url === url ? previous.links : undefined,
  };

  try {
    const result = await analyze(url, settings, settings.deepScan);
    state.result = result;
    const remoteNormalized = result.raw && typeof result.raw.score === "number" && result.raw.level
      ? fromScan(result.raw)
      : fromAnalyze(result);
    state.unified = combine(local, remoteNormalized);
    if (remoteNormalized.components) state.components = remoteNormalized.components;
    if (remoteNormalized.certificate) state.certificate = remoteNormalized.certificate;
    if (remoteNormalized.checks) state.checks = remoteNormalized.checks;
    if (remoteNormalized.intel) state.intel = remoteNormalized.intel;
  } catch (err) {
    state.result = null;
    state.error = err?.message || "Scan failed";
    state.unified = combine(local, null);
  }

  state.kind = "done";
  state.urlUnified = state.unified; // URL-level verdict, before page evidence
  tabState.set(tabId, state);
  await refreshDerived(state, settings);
  paintBadge(tabId, { kind: "done", verdict: state.unified.verdict, score: state.unified.score });

  // If high risk and realtime block is on, check if we need an in-page banner or interstitial
  const host = hostOf(url);
  // The interstitial needs URL-level proof (blocklist, backend verdict, brand spoof); page behaviour alone never blocks.
  if (state.urlUnified.verdict === "dangerous") {
    if (settings.realtimeBlock && !allowedOnce.has(host) && !(await isTrustedHost(host))) {
      chrome.tabs.update(tabId, {
        url: buildWarningUrl(url, state.unified.risk, state.unified.reasons, "block"),
      }).catch(() => {});
    } else {
      warnPage(tabId, url, state.unified).catch(() => {});
    }
  } else if (state.unified.verdict === "suspicious") {
    warnPage(tabId, url, state.unified).catch(() => {});
  }
}

async function warnPage(tabId, url, unified) {
  await chrome.tabs.sendMessage(tabId, {
    type: "olfa:banner",
    data: {
      url,
      verdict: unified.verdict,
      score: unified.score,
      reasons: (unified.reasons || []).slice(0, 3).map((r) => ({ severity: r.severity, text: r.text })),
    },
  });
}

export async function handleNavigation(tabId, url) {
  if (!isHttpUrl(url)) {
    tabState.delete(tabId);
    paintBadge(tabId, { kind: "off" });
    return;
  }
  const settings = await getSettings();
  if (!settings.enabled) {
    tabState.delete(tabId);
    paintBadge(tabId, { kind: "off" });
    return;
  }
  await scanTab(tabId, url, settings);
}

/* ---------- link & QR checking ---------- */

async function checkTargets(pageUrl, targets, settings) {
  const list = Array.isArray(targets) ? targets.slice(0, MAX_TARGETS) : [];
  const prepared = list.map((target) => {
    const value = String(target.value || "");
    const url = target.kind === "qr" ? qrTextToUrl(value) : toHttpUrl(value, pageUrl);
    return { index: target.index, kind: target.kind, url };
  });

  const judged = prepared.map((item) => (item.url ? localCheck(item.url) : null));

  let budget = LINK_CHECK_LIMIT;
  const remoteIndexes = [];
  for (let i = 0; i < prepared.length; i += 1) {
    if (!prepared[i].url || !judged[i]) continue;
    const wantsRemote = prepared[i].kind === "qr" || judged[i].verdict !== "safe";
    if (wantsRemote && budget > 0) {
      remoteIndexes.push(i);
      budget -= 1;
    }
  }

  // Never make the page wait on the backend: after 3.5s fall back to the local verdicts.
  const remoteResults = settings.scanLinks
    ? await Promise.race([
        analyzeMany(remoteIndexes.map((i) => prepared[i].url), settings, { limit: LINK_CHECK_LIMIT }).catch(() => []),
        new Promise((resolve) => setTimeout(() => resolve([]), 3500)),
      ])
    : [];

  const remoteByIndex = new Map();
  remoteIndexes.forEach((idx, pos) => remoteByIndex.set(idx, remoteResults[pos] || null));

  const results = [];
  const verdicts = {};
  for (let i = 0; i < prepared.length; i += 1) {
    const item = prepared[i];
    if (!item.url) continue;
    const remote = remoteByIndex.get(i);
    const merged = combine(judged[i], remote ? (remote.raw?.level ? fromScan(remote.raw) : fromAnalyze(remote)) : null);
    verdicts[item.url] = merged;
    results.push({
      index: item.index,
      kind: item.kind,
      url: item.url,
      verdict: merged.verdict,
      score: merged.score,
      risk: merged.risk,
      sources: (merged.sources || []).join("+"),
      highlight: highlightClass(merged),
      cls: highlightClass(merged),
      reason: reasonText(merged.reasons || []),
    });
  }

  return { results, summary: summarizeLinks(verdicts), count: results.length };
}

/* ---------- event wiring ---------- */

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    handleNavigation(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const state = tabState.get(activeInfo.tabId);
  if (state) {
    paintBadge(activeInfo.tabId, { kind: state.kind, verdict: state.unified?.verdict, score: state.unified?.score });
  } else {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      if (tab?.url) handleNavigation(activeInfo.tabId, tab.url);
    } catch {
      // tab was closed
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
  popupsCreated.delete(tabId);
});

// The floating mascot asks for the current verdict when a page loads.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "olfa:hello" && sender.tab) {
    const st = tabState.get(sender.tab.id);
    sendResponse(st && st.kind === "done" && st.unified ? verdictPayload(sender.tab.id, { kind: "done", verdict: st.unified.verdict }) : { kind: "scanning" });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;
  const type = message && message.type;

  if (type === "olfa:pageData" && tabId) {
    (async () => {
      const settings = await getSettings();
      const state = tabState.get(tabId) || { url: (sender.tab && sender.tab.url) || "", kind: "done" };
      const body = message.data || message; // content script sends a flat message
      state.facts = body.facts || {};
      state.threats = body.threats || {};
      tabState.set(tabId, state);
      try {
        await refreshDerived(state, settings);
        paintBadge(tabId, { kind: "done", verdict: state.unified.verdict, score: state.unified.score });
        sendResponse({ ok: true, verdict: state.unified.verdict, score: state.unified.score });
      } catch (err) {
        sendResponse({ ok: false, error: String(err && err.message) });
      }
    })();
    return true;
  }

  if (type === "olfa:checkLinks" && tabId) {
    (async () => {
      const settings = await getSettings();
      const pageUrl = (sender.tab && sender.tab.url) || "";
      const state = tabState.get(tabId);
      try {
        const judged = await checkTargets(pageUrl, (message.data || message).targets || [], settings);
        if (state) state.links = judged;
        sendResponse(judged);
      } catch (err) {
        sendResponse({ results: [], error: String(err && err.message) });
      }
    })();
    return true;
  }

  if (type === "olfa:getState") {
    (async () => {
      const targetTabId = message.tabId || tabId;
      const state = tabState.get(targetTabId);
      sendResponse(state || null);
    })();
    return true;
  }

  if (type === "olfa:rescan") {
    (async () => {
      const targetTabId = message.tabId;
      if (!targetTabId) return sendResponse({ ok: false });
      const tab = await chrome.tabs.get(targetTabId);
      if (!tab?.url) return sendResponse({ ok: false });
      await clearUrlCache();
      const settings = await getSettings();
      await scanTab(targetTabId, tab.url, settings);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (type === "olfa:trustDomain") {
    (async () => {
      const host = message.host;
      if (!host) return sendResponse({ ok: false });
      const { trustedDomains } = await chrome.storage.local.get({ trustedDomains: [] });
      if (!trustedDomains.includes(host)) {
        trustedDomains.push(host);
        await chrome.storage.local.set({ trustedDomains });
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (type === "olfa:allowOnce") {
    const host = message.host;
    if (host) allowedOnce.add(host);
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

