// Settings + API client for Olfa Master Extension.
// Sends ONLY URLs to the API — never page content.
import { isCacheFresh, CACHE_TTL_MS, mapLimit } from "./logic.js";
import { mockAnalyze, mockReport } from "./mock.js";
import { CONTRACTS } from "../mock/contracts.js";
import { fromScan, fromAnalyze } from "./normalize.js";

export const DEFAULT_SETTINGS = {
  enabled: true,
  useMock: false,
  apiUrl: "https://olfa.onrender.com",
  language: "en",
  scanLinks: true,
  inspectPage: true,
  blockPopups: true,
  realtimeBlock: true,
  deepScan: false,
};

/** Link checks are batched: bounded concurrency. */
export const LINK_CHECK_LIMIT = 10;
export const LINK_CONCURRENCY = 4;

const LANGUAGES = ["en", "hi", "bn"];

/**
 * Read settings from chrome.storage.sync (with local fallback).
 */
export async function getSettings() {
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.sync) {
      const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
      return {
        enabled: Boolean(stored.enabled ?? DEFAULT_SETTINGS.enabled),
        useMock: Boolean(stored.useMock ?? DEFAULT_SETTINGS.useMock),
        apiUrl: String(stored.apiUrl || DEFAULT_SETTINGS.apiUrl).replace(/\/+$/, ""),
        language: LANGUAGES.includes(stored.language) ? stored.language : "en",
        scanLinks: Boolean(stored.scanLinks ?? DEFAULT_SETTINGS.scanLinks),
        inspectPage: Boolean(stored.inspectPage ?? DEFAULT_SETTINGS.inspectPage),
        blockPopups: Boolean(stored.blockPopups ?? DEFAULT_SETTINGS.blockPopups),
        realtimeBlock: Boolean(stored.realtimeBlock ?? DEFAULT_SETTINGS.realtimeBlock),
        deepScan: Boolean(stored.deepScan ?? DEFAULT_SETTINGS.deepScan),
      };
    }
  } catch {
    // fallback if chrome.storage is not available
  }
  return { ...DEFAULT_SETTINGS };
}

/* ---------- URL cache, 10 minutes ---------- */

const CACHE_KEY = "olfa_url_cache_v2";
const CACHE_MAX_ENTRIES = 250;

async function loadCache() {
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get(CACHE_KEY);
      const cache = stored[CACHE_KEY];
      return cache && typeof cache === "object" ? cache : {};
    }
  } catch {
    // fallback
  }
  return {};
}

async function saveCache(cache) {
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [CACHE_KEY]: cache });
    }
  } catch {
    // fallback
  }
}

export async function clearUrlCache() {
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.remove(CACHE_KEY);
    }
  } catch {
    // fallback
  }
}

export async function getCached(url, now = Date.now()) {
  const cache = await loadCache();
  const entry = cache[url];
  if (!entry) return null;
  if (!isFreshEntry(entry, now)) {
    delete cache[url];
    await saveCache(cache);
    return null;
  }
  return entry.result;
}

function isFreshEntry(entry, now) {
  try {
    return isCacheFresh(Number(entry.ts), now, CACHE_TTL_MS);
  } catch {
    return false;
  }
}

function prune(cache) {
  const entries = Object.entries(cache);
  if (entries.length <= CACHE_MAX_ENTRIES) return cache;
  entries.sort((a, b) => Number(a[1].ts) - Number(b[1].ts));
  return Object.fromEntries(entries.slice(-CACHE_MAX_ENTRIES));
}

/* ---------- API calls ---------- */

/**
 * Scan a URL using the Olfa Core API (/scan or /analyze).
 * @param {string} url
 * @param {object} [settings]
 * @param {boolean} [deep]
 */
export async function analyze(url, settings, deep = false) {
  const cfg = settings || (await getSettings());
  const now = Date.now();
  const cacheKey = `${url}|deep:${deep}`;
  const cached = await getCached(cacheKey, now);
  if (cached) return { ...cached, cached: true };

  let raw;
  let normalized;

  if (cfg.useMock) {
    raw = await mockAnalyze(url, CONTRACTS);
    normalized = fromAnalyze(raw);
  } else {
    // Try POST /scan first (the unified Olfa Core engine in improvedML)
    try {
      raw = await apiCall(cfg, "/scan", { url, deep: Boolean(deep || cfg.deepScan), lang: cfg.language });
      normalized = fromScan(raw);
      normalized.raw = raw;
    } catch {
      // Fallback: try POST /analyze (the backend aggregator)
      try {
        raw = await apiCall(cfg, "/analyze", { url });
        normalized = fromAnalyze(raw);
        normalized.raw = raw;
      } catch {
        throw new Error(`Cannot reach Olfa Core at ${cfg.apiUrl}. Make sure python -m uvicorn app:app --port 8790 is running.`);
      }
    }
  }

  const result = { ...normalized, raw };
  const cache = await loadCache();
  cache[cacheKey] = { ts: now, result };
  await saveCache(prune(cache));
  return { ...result, cached: false };
}

export async function analyzeMany(urls, settings, options = {}) {
  const list = (Array.isArray(urls) ? urls : []).slice(0, options.limit ?? LINK_CHECK_LIMIT);
  return mapLimit(list, options.concurrency ?? LINK_CONCURRENCY, (url) => analyze(url, settings, false));
}

/**
 * Send a community report to POST /report.
 * @param {object} payload - { url, verdict, note, category }
 * @param {object} [settings]
 */
export async function sendReport(payload, settings) {
  const cfg = settings || (await getSettings());
  if (cfg.useMock) return mockReport(payload);

  const reporterToken = await getReporterId();
  const body = {
    url: payload.url,
    verdict: payload.verdict || payload.category || "phishing",
    note: payload.note || "",
  };

  return apiCall(cfg, "/report", body, { "X-Reporter-Token": reporterToken });
}

async function apiCall(cfg, endpoint, body, customHeaders = {}) {
  let response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    response = await fetch(`${cfg.apiUrl}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...customHeaders,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timeout);
  } catch (err) {
    throw new Error(`Network failure connecting to ${cfg.apiUrl}${endpoint}: ${err.message}`);
  }
  if (!response.ok) {
    throw new Error(`The API returned HTTP ${response.status} on ${endpoint}`);
  }
  return response.json();
}

/* ---------- reporter identity ---------- */

export async function getReporterId() {
  const KEY = "olfa_reporter_id_v2";
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get(KEY);
      if (stored[KEY]) return stored[KEY];
      const id = `reporter_${Math.random().toString(36).slice(2, 12)}_${Date.now().toString(36)}`;
      await chrome.storage.local.set({ [KEY]: id });
      return id;
    }
  } catch {
    // fallback
  }
  return "anonymous_reporter";
}
