// Olfa Master Extension - Options Controller.
import { getSettings, clearUrlCache } from "./lib/api.js";

const els = {
  apiUrl: document.getElementById("api-url"),
  useMock: document.getElementById("use-mock"),
  realtimeBlock: document.getElementById("realtime-block"),
  blockPopups: document.getElementById("block-popups"),
  scanLinks: document.getElementById("scan-links"),
  deepScan: document.getElementById("deep-scan"),
  mascotOverlay: document.getElementById("mascot-overlay"),
  mascotSize: document.getElementById("mascot-size"),
  mascotSizeVal: document.getElementById("mascot-size-val"),
  grantCookieBtn: document.getElementById("grant-cookie-btn"),
  saveBtn: document.getElementById("save-btn"),
  saveFeedback: document.getElementById("save-feedback"),
};

async function init() {
  const settings = await getSettings();
  els.apiUrl.value = settings.apiUrl || "https://olfa-live.onrender.com";
  els.useMock.checked = Boolean(settings.useMock);
  els.realtimeBlock.checked = Boolean(settings.realtimeBlock);
  els.blockPopups.checked = Boolean(settings.blockPopups);
  els.scanLinks.checked = Boolean(settings.scanLinks);
  els.deepScan.checked = Boolean(settings.deepScan);
  const m = await chrome.storage.sync.get({ mascotOverlay: true, mascotSize: 116 });
  els.mascotOverlay.checked = m.mascotOverlay !== false;
  els.mascotSize.value = m.mascotSize;
  els.mascotSizeVal.textContent = m.mascotSize;
  els.mascotSize.disabled = !els.mascotOverlay.checked;
  els.mascotOverlay.addEventListener("change", () => {
    els.mascotSize.disabled = !els.mascotOverlay.checked;
    chrome.storage.sync.set({ mascotOverlay: els.mascotOverlay.checked });
  });
  els.mascotSize.addEventListener("input", () => {
    els.mascotSizeVal.textContent = els.mascotSize.value;
    chrome.storage.sync.set({ mascotSize: Number(els.mascotSize.value) });
  });

  checkCookiePermission();

  els.grantCookieBtn?.addEventListener("click", async () => {
    try {
      const granted = await chrome.permissions.request({
        permissions: ["cookies"],
        origins: ["<all_urls>"],
      });
      if (granted) {
        els.grantCookieBtn.textContent = "✓ Permission Granted";
        els.grantCookieBtn.disabled = true;
      }
    } catch (err) {
      alert("Could not request permission: " + err.message);
    }
  });

  els.saveBtn?.addEventListener("click", async () => {
    const next = {
      apiUrl: els.apiUrl.value.trim().replace(/\/+$/, ""),
      useMock: els.useMock.checked,
      realtimeBlock: els.realtimeBlock.checked,
      blockPopups: els.blockPopups.checked,
      scanLinks: els.scanLinks.checked,
      deepScan: els.deepScan.checked,
      mascotOverlay: els.mascotOverlay.checked,
      mascotSize: Number(els.mascotSize.value),
    };
    await chrome.storage.sync.set(next);
    await clearUrlCache();
    els.saveFeedback.hidden = false;
    setTimeout(() => {
      els.saveFeedback.hidden = true;
    }, 2500);
  });
}

async function checkCookiePermission() {
  try {
    const hasPerm = await chrome.permissions.contains({
      permissions: ["cookies"],
      origins: ["<all_urls>"],
    });
    if (hasPerm) {
      els.grantCookieBtn.textContent = "✓ Granted";
      els.grantCookieBtn.disabled = true;
    }
  } catch {
    // fallback
  }
}

document.addEventListener("DOMContentLoaded", init);

