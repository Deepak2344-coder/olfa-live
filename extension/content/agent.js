// Content agent (isolated world, document_idle).
//
// Collects plain facts about the page and asks the service worker what to do:
//
//   forms + storage keys + resource hosts + fingerprint calls  -> olfa:pageData
//   link hrefs + decoded QR payloads                            -> olfa:checkLinks
//
// It never decides risk itself: every judgement lives in the pure modules under
// lib/ and runs in the service worker, so there is one implementation and it is
// covered by `node --test`. Nothing here reads form values, cookie values or
// page text beyond inline <script> bodies.
(() => {
  "use strict";

  if (window.__olfaAgent) return;
  window.__olfaAgent = true;
  const stage = (s) => {
    try { document.documentElement.setAttribute("data-olfa-stage", s); } catch { /* ignore */ }
  };
  try { document.documentElement.setAttribute("data-olfa-agent", "1.1.0"); } catch { /* ignore */ }

  const MAX_LINKS = 100;
  const MAX_QR_DECODES = 12;
  const MAX_QR_DIM = 640;
  const MAX_REQUESTS = 200;
  const MAX_SCRIPT_CHARS = 4000;
  const RESCAN_DELAY_MS = 1800;
  const MAX_RESCANS = 4;

  const fingerprintCalls = new Set();
  const seenQrElements = new WeakSet();
  let rescans = 0;

  /* ---------- fingerprint reports from the MAIN-world probe ---------- */

  window.addEventListener("message", (event) => {
    const data = event && event.data;
    if (data && data.source === "olfa-fp" && typeof data.api === "string") {
      fingerprintCalls.add(data.api.slice(0, 40));
    }
  });

  /* ---------- fact collection ---------- */

  function collectForms() {
    const out = [];
    const forms = document.querySelectorAll("form");
    for (let i = 0; i < forms.length && out.length < 20; i += 1) {
      const form = forms[i];
      let action = "";
      try {
        action = form.action ? new URL(form.action, location.href).href : location.href;
      } catch {
        action = location.href;
      }
      const fields = [];
      const inputs = form.querySelectorAll("input,select,textarea");
      for (let j = 0; j < inputs.length && fields.length < 25; j += 1) {
        const input = inputs[j];
        // Names and types ONLY. Values never leave the browser.
        fields.push({
          name: String(input.name || "").slice(0, 40),
          type: String(input.type || "").slice(0, 20),
          autocomplete: String(input.getAttribute("autocomplete") || "").slice(0, 40),
          id: String(input.id || "").slice(0, 40),
        });
      }
      out.push({ action, method: String(form.method || "get").toUpperCase(), fields });
    }
    return out;
  }

  function collectStorage() {
    const read = (store) => {
      try {
        return Object.keys(store).slice(0, 50);
      } catch {
        return [];
      }
    };
    return { local: read(window.localStorage), session: read(window.sessionStorage) };
  }

  function collectRequests() {
    const entries = [];
    const seen = new Set();
    try {
      const resources = performance.getEntriesByType("resource");
      for (const entry of resources) {
        if (entries.length >= MAX_REQUESTS) break;
        const url = String(entry.name || "");
        if (!url || seen.has(url)) continue;
        seen.add(url);
        entries.push({ url, method: "GET", type: String(entry.initiatorType || "other") });
      }
    } catch {
      /* performance API unavailable */
    }
    return entries;
  }

  function collectHiddenIframes() {
    const out = [];
    const frames = document.querySelectorAll("iframe");
    for (let i = 0; i < frames.length && out.length < 10; i += 1) {
      const frame = frames[i];
      let rect;
      let style;
      try {
        rect = frame.getBoundingClientRect();
        style = getComputedStyle(frame);
      } catch {
        continue;
      }
      const invisible =
        rect.width <= 1 ||
        rect.height <= 1 ||
        style.display === "none" ||
        style.visibility === "hidden" ||
        Number(style.opacity) === 0;
      if (invisible) {
        out.push({ src: String(frame.src || frame.getAttribute("src") || "").slice(0, 200), width: rect.width, height: rect.height });
      }
    }
    return out;
  }

  function collectOverlays() {
    const out = [];
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    if (!vw || !vh) return out;

    let nodes;
    try {
      nodes = document.querySelectorAll("div,section,iframe,object,embed");
    } catch {
      return out;
    }

    const cap = Math.min(nodes.length, 1500);
    for (let i = 0; i < cap && out.length < 5; i += 1) {
      const el = nodes[i];
      if (el.id === "olfa-banner" || (el.closest && el.closest("#olfa-banner"))) continue;
      let rect;
      let style;
      try {
        rect = el.getBoundingClientRect();
        style = getComputedStyle(el);
      } catch {
        continue;
      }
      const area = (rect.width * rect.height) / (vw * vh);
      // A near-invisible element covering most of the viewport is the
      // clickjacking signature; genuine modals are not transparent.
      if (area >= 0.5 && Number(style.opacity) <= 0.15) {
        out.push({ tag: el.tagName.toLowerCase(), description: `${Math.round(area * 100)}% of the viewport, opacity ${style.opacity}` });
      }
    }
    return out;
  }

  function collectScripts() {
    const out = [];
    const scripts = document.querySelectorAll("script:not([src])");
    for (let i = 0; i < scripts.length && out.length < 5; i += 1) {
      const text = String(scripts[i].textContent || "");
      if (text.length >= 200) out.push(text.slice(0, MAX_SCRIPT_CHARS));
    }
    return out;
  }

  /* ---------- QR decoding (in the page, where canvas works) ---------- */

  function decodeCanvas(canvas) {
    try {
      const w = canvas.width;
      const h = canvas.height;
      if (!w || !h) return null;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (!ctx) return null;
      const image = ctx.getImageData(0, 0, w, h);
      const code = typeof window.jsQR === "function" ? window.jsQR(image.data, w, h) : null;
      return code && code.data ? String(code.data).slice(0, 500) : null;
    } catch {
      return null; // tainted or unreadable canvas
    }
  }

  function decodeImage(img) {
    try {
      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      if (!w || !h) return null;
      const scale = Math.min(1, MAX_QR_DIM / Math.max(w, h));
      const cw = Math.max(1, Math.round(w * scale));
      const ch = Math.max(1, Math.round(h * scale));
      const canvas = document.createElement("canvas");
      canvas.width = cw;
      canvas.height = ch;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (!ctx) return null;
      ctx.drawImage(img, 0, 0, cw, ch);
      const image = ctx.getImageData(0, 0, cw, ch);
      const code = typeof window.jsQR === "function" ? window.jsQR(image.data, cw, ch) : null;
      return code && code.data ? String(code.data).slice(0, 500) : null;
    } catch {
      return null; // cross-origin image without CORS: skip quietly
    }
  }

  function isQrSized(width, height) {
    const w = Number(width);
    const h = Number(height);
    if (!Number.isFinite(w) || !Number.isFinite(h)) return false;
    if (w < 48 || h < 48) return false;
    const ratio = w / h;
    return ratio <= 1.35 && ratio >= 1 / 1.35;
  }

  function collectQrTargets() {
    const targets = [];
    let decodes = 0;

    const canvases = document.querySelectorAll("canvas");
    for (let i = 0; i < canvases.length && decodes < MAX_QR_DECODES; i += 1) {
      const canvas = canvases[i];
      if (seenQrElements.has(canvas) || !isQrSized(canvas.width, canvas.height)) continue;
      seenQrElements.add(canvas);
      decodes += 1;
      const text = decodeCanvas(canvas);
      if (text) targets.push({ element: canvas, text });
    }

    const images = document.querySelectorAll("img");
    for (let i = 0; i < images.length && decodes < MAX_QR_DECODES; i += 1) {
      const img = images[i];
      if (seenQrElements.has(img)) continue;
      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      if (!isQrSized(w, h)) continue;
      seenQrElements.add(img);
      decodes += 1;
      const text = decodeImage(img);
      if (text) targets.push({ element: img, text });
    }

    return targets;
  }

  /* ---------- messaging ---------- */

  function send(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) resolve(null);
          else resolve(response || null);
        });
      } catch {
        resolve(null); // extension reloaded under us
      }
    });
  }

  function applyHighlight(element, className, result) {
    if (!element) return;
    try {
      element.classList.remove("olfa-unsafe", "olfa-suspicious"); // latest verdict wins
      element.removeAttribute("data-olfa-level");
      element.setAttribute("data-olfa-verdict", String(result.verdict || "safe"));
      element.setAttribute("data-olfa-risk", String(result.risk ?? ""));
      element.setAttribute("data-olfa-sources", String(result.sources || ""));
      if (!className) return;
      element.classList.add(className);
      element.setAttribute("data-olfa-level", className === "olfa-unsafe" ? "dangerous" : "suspicious");
      if (result.reason && !element.getAttribute("title")) element.setAttribute("title", `Olfa: ${result.reason}`);
    } catch {
      /* detached node */
    }
  }

  /* ---------- the scan pass ---------- */

  async function scan() {
    const url = location.href;
    stage("scan-start");

    const pageData = await send({
      type: "olfa:pageData",
      url,
      facts: {
        pageUrl: url,
        forms: collectForms(),
        storageKeys: collectStorage(),
        requests: collectRequests(),
        fingerprintCalls: Array.from(fingerprintCalls).slice(0, 20),
      },
      threats: {
        hiddenIframes: collectHiddenIframes(),
        overlays: collectOverlays(),
        scripts: collectScripts(),
        apiCalls: Array.from(fingerprintCalls).slice(0, 20),
      },
    });
    stage(pageData ? "pagedata-ok" : "pagedata-null(continuing)"); // link checks must not depend on this

    // Links: the worker normalises hrefs, so the same logic is unit tested.
    const anchors = document.querySelectorAll("a[href]");
    const linkElements = [];
    const targets = [];
    for (let i = 0; i < anchors.length && targets.length < MAX_LINKS; i += 1) {
      const anchor = anchors[i];
      const href = anchor.getAttribute("href");
      if (!href) continue;
      linkElements.push(anchor);
      targets.push({ index: linkElements.length - 1, kind: "link", value: href });
    }

    const qrTargets = collectQrTargets();
    for (const qr of qrTargets) {
      linkElements.push(qr.element);
      targets.push({ index: linkElements.length - 1, kind: "qr", value: qr.text });
    }

    if (!targets.length) { stage("no-targets"); return; }
    stage("links-sent:" + targets.length);

    const response = await send({ type: "olfa:checkLinks", url, targets });
    if (!response || !Array.isArray(response.results)) { stage("links-null"); return; }
    stage("links-done:" + response.results.length);

    for (const result of response.results) {
      const element = linkElements[result.index];
      applyHighlight(element, result.cls || result.highlight || null, result);
    }
  }

  function scheduleRescan() {
    if (rescans >= MAX_RESCANS) return;
    rescans += 1;
    setTimeout(() => {
      scan().catch(() => {});
    }, RESCAN_DELAY_MS);
  }

  function start() {
    scan().catch(() => {});

    // Single-page apps add links after load; re-scan a bounded number of times.
    try {
      const observer = new MutationObserver((records) => {
        for (const record of records) {
          if (record.addedNodes && record.addedNodes.length) {
            scheduleRescan();
            return;
          }
        }
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => observer.disconnect(), 15000);
    } catch {
      /* DOM unavailable */
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
