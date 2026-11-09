// Olfa floating mascot: Hachi lives in the corner of the page and reacts to the verdict.
// The dog is rendered in an extension-owned frame, so the page cannot style or read it.
(() => {
  if (window.top !== window || !/^https?:$/.test(location.protocol)) return;
  if (document.getElementById("olfa-mascot-frame")) return;

  let dogSize = 116, kind = "compact";
  const dims = (k) => { const w = dogSize + 34, h = dogSize + 44; return k === "wide" ? { w: w + 230, h } : k === "panel" ? { w: w + 250, h: Math.max(h, 300) } : { w, h }; };
  let frame = null, enabled = true, ready = false, queue = [], pos = { right: 16, bottom: 16 };
  let verdict = "scanning", napping = false, hoverLink = null, restore = 0, lastLook = 0;

  const TEXT = {
    scanning:   { title: null },
    safe:       { title: "Smells safe to me!", ttl: 3800, mood: "safe" },
    suspicious: { title: "Hmm, something smells off.", mood: "suspicious" },
    dangerous:  { title: "Woof! Stay away!", mood: "dangerous" },
  };

  function send(msg) { if (!frame) return; if (!ready) { queue.push(msg); return; } frame.contentWindow.postMessage({ olfa: true, ...msg }, "*"); }
  function place() { frame.style.right = pos.right + "px"; frame.style.bottom = pos.bottom + "px"; }
  function size(k) { kind = k; const s = dims(k); frame.style.width = s.w + "px"; frame.style.height = s.h + "px"; }

  function pose(v, reason) {
    verdict = v;
    if (napping) return;
    const t = TEXT[v] || TEXT.scanning;
    send({ pose: v, title: t.title, sub: (v === "suspicious" || v === "dangerous") ? reason : "", mood: t.mood, ttl: t.ttl, info: { url: location.href, verdict: v, score: lastInfo.score, reasons: lastInfo.reasons } });
  }

  function build() {
    frame = document.createElement("iframe");
    frame.id = "olfa-mascot-frame";
    frame.src = chrome.runtime.getURL("mascot.html");
    frame.setAttribute("title", "Hachi, your Olfa shield mascot");
    frame.setAttribute("allowtransparency", "true");
    frame.style.cssText = "all:initial;position:fixed;border:0;background:transparent;z-index:2147483646;color-scheme:normal;pointer-events:auto;";
    size("compact"); place();
    document.documentElement.appendChild(frame);
  }

  window.addEventListener("message", (e) => {
    if (!frame || e.source !== frame.contentWindow || !e.data || e.data.olfa !== true) return;
    const d = e.data;
    if (d.ready) { ready = true; send({ cfg: { dogSize } }); queue.splice(0).forEach(send); }
    if (d.size) size(d.size);
    if (d.drag) {
      pos.right = Math.max(0, Math.min(window.innerWidth - 120, pos.right - d.drag.dx));
      pos.bottom = Math.max(0, Math.min(window.innerHeight - 120, pos.bottom - d.drag.dy));
      place();
    }
    if (d.dropped) { try { chrome.storage.local.set({ mascotPos: pos }); } catch {} }
    if (d.pet) {
      napping = false;
      send({ pose: "pet", title: "Woof! 💛", sub: "", mood: "safe", ttl: 1800 });
      restoreSoon(2200);
    }
    if (d.nap) { napping = true; size("compact"); send({ pose: "nap" }); }
  });

  function restoreSoon(ms) { clearTimeout(restore); restore = setTimeout(() => pose(verdict, lastReason), ms); }

  let lastReason = "", lastInfo = { score: null, reasons: [] };
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== "olfa:verdict" || !frame) return;
    lastReason = msg.reason || "";
    lastInfo = { score: msg.score ?? null, reasons: msg.reasons || [] };
    frame.style.display = msg.kind === "off" ? "none" : "";
    if (msg.kind === "off") return;
    if (msg.kind === "error") return pose("idle");
    if (msg.kind === "scanning") return pose("scanning");
    if (msg.verdict) pose(msg.verdict, lastReason);
  });

  // gesture: warn when the pointer rests on a link Olfa flagged
  document.addEventListener("mouseover", (e) => {
    if (!frame || napping) return;
    const a = e.target.closest && e.target.closest("[data-olfa-verdict]");
    if (!a || a === hoverLink) return;
    const v = a.getAttribute("data-olfa-verdict");
    if (v !== "dangerous" && v !== "suspicious") return;
    hoverLink = a;
    send({ pose: v, title: v === "dangerous" ? "Don't click that link!" : "That link smells odd…", sub: "Olfa flagged it.", mood: v, ttl: 3000 });
    restoreSoon(3300);
    a.addEventListener("mouseleave", () => { hoverLink = null; }, { once: true });
  }, true);

  // gesture: head turns toward the cursor (3D parallax), throttled
  document.addEventListener("mousemove", (e) => {
    if (!frame || !ready || napping) return;
    const now = performance.now(); if (now - lastLook < 60) return; lastLook = now;
    const r = frame.getBoundingClientRect();
    const cx = r.right - 70, cy = r.bottom - 70;
    const x = Math.max(-1, Math.min(1, (e.clientX - cx) / 600)), y = Math.max(-1, Math.min(1, (e.clientY - cy) / 400));
    send({ look: { x, y } });
  }, { passive: true });

  async function start() {
    try {
      const s = await chrome.storage.sync.get({ mascotOverlay: true, mascotSize: 116 });
      enabled = s.mascotOverlay !== false;
      const l = await chrome.storage.local.get({ mascotPos: null });
      dogSize = Math.max(64, Math.min(180, Number(s.mascotSize) || 116));
      if (l.mascotPos) pos = l.mascotPos;
    } catch {}
    if (!enabled) return;
    build();
    try {
      const r = await chrome.runtime.sendMessage({ type: "olfa:hello" });
      if (r?.verdict) { lastReason = r.reason || ""; lastInfo = { score: r.score ?? null, reasons: r.reasons || [] }; pose(r.verdict, lastReason); } else pose("scanning");
    } catch { pose("scanning"); }
  }
  chrome.storage.onChanged.addListener((c, area) => {
    if (area === "sync" && c.mascotSize && frame) {
      dogSize = Math.max(64, Math.min(180, Number(c.mascotSize.newValue) || 116));
      size(kind); send({ cfg: { dogSize } });
    }
    if (area === "sync" && c.mascotOverlay) {
      if (c.mascotOverlay.newValue === false) { frame?.remove(); frame = null; ready = false; }
      else if (!frame) start();
    }
  });
  start();
})();
