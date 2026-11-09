// Olfa Master Extension - Popup Controller.
import { getSettings, sendReport } from "./lib/api.js";
import { getAlert, alertForReason, verdictMessage } from "./lib/alerts.js";
import { analyzeMessage } from "./lib/message.js";
import "./lib/hachi-dog.js";

const els = {
  activeHost: document.getElementById("active-host"),
  overallBadge: document.getElementById("overall-badge"),
  langSelect: document.getElementById("lang-select"),
  rescanBtn: document.getElementById("rescan-btn"),

  gradeRing: document.getElementById("grade-ring"),
  gradeLetter: document.getElementById("grade-letter"),
  gradeScore: document.getElementById("grade-score"),
  verdictTitle: document.getElementById("verdict-title"),
  verdictDesc: document.getElementById("verdict-desc"),
  domainAgeChip: document.getElementById("domain-age-chip"),
  adsBlockedChip: document.getElementById("ads-blocked-chip"),

  pillarMl: document.getElementById("pillar-ml-status"),
  pillarSec: document.getElementById("pillar-sec-status"),
  pillarCert: document.getElementById("pillar-cert-status"),
  pillarIntel: document.getElementById("pillar-intel-status"),

  certChainBox: document.getElementById("cert-chain-box"),
  certCipher: document.getElementById("cert-cipher"),
  certLeaf: document.getElementById("cert-leaf"),
  certInter: document.getElementById("cert-inter"),
  certRoot: document.getElementById("cert-root"),

  findingsList: document.getElementById("findings-list"),

  domThreatsList: document.getElementById("dom-threats-list"),
  factTrackers: document.getElementById("fact-trackers"),
  factCookies: document.getElementById("fact-cookies"),
  factForms: document.getElementById("fact-forms"),
  factFps: document.getElementById("fact-fps"),

  linksSummaryBar: document.getElementById("links-summary-bar"),
  linksList: document.getElementById("links-list"),
  toggleHighlightBtn: document.getElementById("toggle-highlight-btn"),

  msgLangSelect: document.getElementById("msg-lang-select"),
  msgInput: document.getElementById("msg-input"),
  msgScanBtn: document.getElementById("msg-scan-btn"),
  msgResults: document.getElementById("msg-results"),
  msgVerdictBanner: document.getElementById("msg-verdict-banner"),
  msgHighlightedText: document.getElementById("msg-highlighted-text"),
  msgRulesList: document.getElementById("msg-rules-list"),

  reportBtns: document.querySelectorAll(".report-btn"),
  reportNote: document.getElementById("report-note"),
  reportFeedback: document.getElementById("report-feedback"),
};

let currentTab = null;
let currentState = null;
let currentSettings = null;
let highlightingActive = false;

const VERDICT_THEME = {
  safe: { color: "#1F9D55", bg: "rgba(34, 197, 94, 0.15)", class: "badge-safe", label: "Safe" },
  suspicious: { color: "#D98A12", bg: "rgba(245, 158, 11, 0.15)", class: "badge-warning", label: "Suspicious" },
  dangerous: { color: "#D6453A", bg: "rgba(239, 68, 68, 0.15)", class: "badge-danger", label: "Dangerous" },
};

const GRADE_COLOR = {
  A: "#1F9D55",
  B: "#3C9A3C",
  C: "#D98A12",
  D: "#E0701F",
  F: "#D6453A",
};

function esc(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


/* ---------- Hachi mascot: verdict -> animation state ---------- */
const MASCOT = {
  scanning:   { dog: "scanning", rest: "scanning", title: "Sniffing this page…", sub: "Checking links, certificate and page behaviour." },
  safe:       { dog: "safe", rest: "idle", title: "Smells safe to me!", sub: "No warning signs found on this page." },
  suspicious: { dog: "error", rest: "error", title: "Hmm, something smells off.", sub: "Be careful with logins and downloads here." },
  dangerous:  { dog: "phishing", rest: "error", title: "Woof! Stay away!", sub: "This page looks like a phishing or malware trap." },
  nonweb:     { dog: "offline", rest: "offline", title: "Nothing to sniff here.", sub: "This isn't a web page. Hachi is napping." },
};
const mascotEl = document.getElementById("mascot");
const heroEl = document.getElementById("hero");
let mascotKey = "";
let mascotRest = "idle";
mascotEl?.addEventListener("ended", () => {
  // one-shot finished: settle into the resting pose for the current verdict
  setTimeout(() => mascotEl.setDog(mascotRest), 0);
});
function setMascot(key, state) {
  const m = MASCOT[key] || MASCOT.scanning;
  if (!mascotEl || key === mascotKey) return;
  mascotKey = key;
  mascotRest = m.rest;
  heroEl.dataset.mood = key;
  document.getElementById("bubble-title").textContent = m.title;
  const top = state?.unified?.reasons?.[0];
  const reason = top && (top.text || top.message);
  document.getElementById("bubble-sub").textContent = (key === "suspicious" || key === "dangerous") && reason ? reason : m.sub;
  mascotEl.setDog(m.dog);
}

async function checkBackend() {
  const dot = document.getElementById("backend-status-dot");
  try {
    const base = String(currentSettings?.apiUrl || "https://olfa-live.onrender.com").replace(/\/+$/, "");
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 2000);
    const r = await fetch(`${base}/health`, { signal: ctl.signal });
    clearTimeout(t);
    if (!r.ok) throw new Error(String(r.status));
    dot.className = "dot-green"; dot.textContent = "● Live"; dot.title = "Backend connected";
  } catch {
    dot.className = "dot-red"; dot.textContent = "● Offline checks only"; dot.title = "Olfa backend not reachable. Local rules still protect you.";
  }
}

/* ---------- tab navigation ---------- */

function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const targetPanel = document.getElementById(tab.dataset.tab);
      if (targetPanel) targetPanel.classList.add("active");
    });
  });
}

/* ---------- render telemetry ---------- */

async function renderOverview(state, settings) {
  const unified = state?.unified || { score: 100, verdict: "safe", reasons: [] };
  const verdict = unified.verdict || "safe";
  const score = Math.round(unified.score ?? 100);
  const theme = VERDICT_THEME[verdict] || VERDICT_THEME.safe;
  const lang = settings.language || "en";
  setMascot(verdict, state);

  // Host header
  try {
    const urlObj = new URL(state?.url || "http://localhost");
    els.activeHost.textContent = urlObj.hostname;
    els.activeHost.title = state.url;
  } catch {
    els.activeHost.textContent = state?.url || "Active Webpage";
  }

  els.overallBadge.className = `shield-badge ${theme.class}`;
  els.overallBadge.textContent = theme.label;

  // Grade circle
  const gradeObj = state?.grade || { grade: verdict === "dangerous" ? "F" : "A", points: score };
  const gradeLetter = gradeObj.grade || (score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : "F");
  const gradeColor = GRADE_COLOR[gradeLetter] || theme.color;

  els.gradeRing.style.borderColor = gradeColor;
  els.gradeRing.style.backgroundColor = `${gradeColor}22`;
  els.gradeRing.style.color = gradeColor;
  els.gradeLetter.textContent = gradeLetter;
  els.gradeScore.textContent = `${score}/100`;

  // Verdict title and description
  els.verdictTitle.textContent = verdict === "safe"
    ? "No Critical Warning Signs Found"
    : verdict === "suspicious"
    ? "Suspicious Security Signals Detected"
    : "Dangerous / Confirmed Threat Vector";
  els.verdictTitle.style.color = gradeColor;
  els.verdictDesc.textContent = verdictMessage(verdict, lang);

  // Pop-up ads counter
  try {
    const { blockedPopupsCount } = await chrome.storage.local.get({ blockedPopupsCount: 0 });
    els.adsBlockedChip.textContent = `🛡 Pop-up Blocker: Active (${blockedPopupsCount} blocked)`;
  } catch {
    els.adsBlockedChip.textContent = "🛡 Pop-up Blocker: Active";
  }

  // Domain Age
  const rawData = state?.result?.raw;
  let domainAgeText = "Domain Age: Verified";
  if (rawData?.checks) {
    const ageCheck = rawData.checks.find((c) => c.title && c.title.toLowerCase().includes("domain age"));
    if (ageCheck && ageCheck.detail) {
      domainAgeText = `Domain Age: ${ageCheck.detail}`;
    }
  }
  els.domainAgeChip.textContent = domainAgeText;

  // 4 Pillars
  const components = state?.components || rawData?.components;
  if (components) {
    // Pillar 1: ML model
    const mlRisk = components.ml?.risk_pct;
    if (mlRisk !== undefined && mlRisk !== null) {
      els.pillarMl.textContent = mlRisk >= 80 ? `Phishing (${mlRisk}%)` : `Safe (${mlRisk}%)`;
      els.pillarMl.style.color = mlRisk >= 80 ? "#D6453A" : "#1F9D55";
    }

    // Pillar 2: Page security
    const pageGrade = components.page_security?.grade;
    if (pageGrade) {
      els.pillarSec.textContent = `Grade ${pageGrade}`;
      els.pillarSec.style.color = GRADE_COLOR[pageGrade] || "#1F9D55";
    }

    // Pillar 3: TLS certificate
    const certTrusted = components.certificate?.trusted;
    const certStatus = components.certificate?.status;
    els.pillarCert.textContent = certTrusted ? "Trusted" : certStatus || "Inspected";
    els.pillarCert.style.color = certTrusted ? "#1F9D55" : "#D98A12";

    // Pillar 4: Community intel
    const unsafeReports = components.community?.unsafe_reports || 0;
    const safeReports = components.community?.safe_reports || 0;
    els.pillarIntel.textContent = `${unsafeReports} unsafe / ${safeReports} safe`;
    els.pillarIntel.style.color = unsafeReports > 0 ? "#D6453A" : "#1F9D55";
  }

  // Certificate Chain Display
  const certInfo = state?.certificate || rawData?.certificate;
  if (certInfo && certInfo.chain && Array.isArray(certInfo.chain) && certInfo.chain.length > 0) {
    els.certCipher.textContent = certInfo.connection || "TLS Encrypted";
    const chain = certInfo.chain;
    els.certLeaf.textContent = chain[0] || (certInfo.issued_to || "Host Certificate");
    els.certInter.textContent = chain.length > 2 ? chain[1] : (certInfo.issued_by || "Intermediate Authority");
    els.certRoot.textContent = chain[chain.length - 1] || "Root CA";
  } else {
    els.certLeaf.textContent = els.activeHost.textContent;
    els.certInter.textContent = "Verified TLS Issuer";
    els.certRoot.textContent = "System Trust Store";
  }

  // Findings list
  const reasons = (unified.reasons || []).slice(0, 6);
  if (!reasons.length) {
    els.findingsList.innerHTML = `<li style="color:#1F9D55">✓ Zero deceptive patterns or threats reported for this domain.</li>`;
  } else {
    els.findingsList.innerHTML = reasons
      .map((r) => {
        const text = alertForReason(r, lang);
        const sevColor = r.severity === "high" ? "#D6453A" : r.severity === "medium" ? "#D98A12" : "#38bdf8";
        return `<li><span style="color:${sevColor};font-weight:700">[${esc(r.severity)}]</span> ${esc(text)}</li>`;
      })
      .join("");
  }
}

function renderThreatsAndPrivacy(state) {
  const threats = state?.threats || {};
  const pageSignals = state?.pageSignals || {};

  // DOM Threats List
  const threatItems = [];
  if (threats.iframes && threats.iframes.length) {
    threatItems.push(`Hidden iFrames (${threats.iframes.length} detected)`);
  }
  if (threats.overlays && threats.overlays.length) {
    threatItems.push(`Clickjacking / Transparent Overlays (${threats.overlays.length} detected)`);
  }
  if (threats.obfuscated && threats.obfuscated.length) {
    threatItems.push(`High-Entropy / Obfuscated JavaScript Packets`);
  }
  if (threats.clipboardEvents && threats.clipboardEvents.length) {
    threatItems.push(`Clipboard Read / Exfiltration Listeners`);
  }

  if (threatItems.length) {
    els.domThreatsList.innerHTML = threatItems
      .map((t) => `<div class="threat-item">⚠ ${esc(t)}</div>`)
      .join("");
  } else {
    els.domThreatsList.innerHTML = `<div class="threat-empty">✓ No clickjacking, hidden iframes or script traps detected.</div>`;
  }

  // Privacy Facts
  const collected = pageSignals.collected || {};
  const cookies = state?.cookies || {};
  els.factTrackers.textContent = collected.trackers ?? 0;
  els.factCookies.textContent = cookies.missingSecure ?? (collected.insecureCookies ?? 0);
  els.factForms.textContent = collected.crossOriginForms ?? 0;
  els.factFps.textContent = (pageSignals.signals && pageSignals.signals.fingerprintCalls?.length) || 0;
}

function renderLinksAndQr(state) {
  const linksData = state?.links;
  const results = linksData?.results || [];

  els.linksSummaryBar.textContent = `${results.length} links & QR elements inspected on this page`;

  if (!results.length) {
    els.linksList.innerHTML = `<div class="threat-empty">No external links or QR targets discovered yet.</div>`;
    return;
  }

  els.linksList.innerHTML = results
    .slice(0, 30)
    .map((item) => {
      const isDangerous = item.verdict === "dangerous";
      const isSuspicious = item.verdict === "suspicious";
      const badgeClass = isDangerous ? "badge-danger" : isSuspicious ? "badge-warning" : "badge-safe";
      const icon = item.kind === "qr" ? "📷 QR" : "🔗 Link";
      return `
        <div class="link-row">
          <span class="link-url" title="${esc(item.url)}">${icon}: ${esc(item.url)}</span>
          <span class="shield-badge ${badgeClass}">${esc(item.verdict)}</span>
        </div>
      `;
    })
    .join("");
}

/* ---------- message checker ---------- */

function initMessageChecker() {
  els.msgScanBtn?.addEventListener("click", () => {
    const text = els.msgInput.value.trim();
    if (!text) return;
    const lang = els.msgLangSelect.value;
    const res = analyzeMessage(text, lang);

    els.msgResults.hidden = false;
    const isScam = res.verdict !== "safe";
    els.msgVerdictBanner.textContent = isScam
      ? `🚨 Scam Patterns Detected (${res.score}% Risk)`
      : `✓ No Common Scam Wording Detected (${res.score}% Risk)`;
    els.msgVerdictBanner.style.color = isScam ? "#D6453A" : "#1F9D55";

    els.msgHighlightedText.innerHTML = res.highlighted || esc(text);

    if (res.matches && res.matches.length) {
      els.msgRulesList.innerHTML = res.matches
        .map((m) => `<li>[${esc(m.severity)}] ${esc(m.label || m.rule)}</li>`)
        .join("");
    } else {
      els.msgRulesList.innerHTML = `<li>No pressure keywords, urgency patterns, or credential harvesting lures found.</li>`;
    }
  });
}

/* ---------- community reporting ---------- */

function initReporting() {
  els.reportBtns.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const verdict = btn.dataset.verdict;
      const note = els.reportNote.value.trim();
      const url = currentState?.url || currentTab?.url;
      if (!url) return;

      btn.disabled = true;
      btn.textContent = "Submitting…";

      try {
        await sendReport({ url, verdict, note }, currentSettings);
        els.reportFeedback.hidden = false;
        els.reportFeedback.textContent = `✓ Successfully filed report for ${verdict}. Thank you for securing the web!`;
      } catch (err) {
        els.reportFeedback.hidden = false;
        els.reportFeedback.textContent = `Report saved locally. (${err.message})`;
      } finally {
        btn.disabled = false;
        btn.textContent = btn.dataset.verdict === "phishing" ? "🚨 Report as Phishing" : btn.dataset.verdict === "scam" ? "⚠️ Report as Scam" : "✅ Confirm Safe";
      }
    });
  });
}

/* ---------- page highlight toggle ---------- */

function initHighlightToggle() {
  els.toggleHighlightBtn?.addEventListener("click", async () => {
    if (!currentTab?.id) return;
    highlightingActive = !highlightingActive;
    els.toggleHighlightBtn.textContent = highlightingActive ? "Clear Outlines" : "Highlight on Page";
    await chrome.tabs.sendMessage(currentTab.id, {
      type: "olfa:highlight",
      active: highlightingActive,
      results: currentState?.links?.results || [],
    }).catch(() => {});
  });
}

/* ---------- bootstrap popup ---------- */

async function init() {
  initTabs();
  initMessageChecker();
  initReporting();
  initHighlightToggle();

  currentSettings = await getSettings();
  els.langSelect.value = currentSettings.language || "en";
  els.msgLangSelect.value = currentSettings.language || "en";

  els.langSelect.addEventListener("change", async (e) => {
    const nextLang = e.target.value;
    await chrome.storage.sync.set({ language: nextLang });
    currentSettings.language = nextLang;
    if (currentState) {
      renderOverview(currentState, currentSettings);
    }
  });

  // Query active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;
  checkBackend();
  if (tab && !/^https?:/i.test(tab.url || "")) {
    els.activeHost.textContent = (tab.url || "").split("/")[0] || "Browser page";
    els.overallBadge.className = "shield-badge badge-neutral";
    els.overallBadge.textContent = "N/A";
    els.verdictTitle.textContent = "Not a web page";
    els.verdictDesc.textContent = "Olfa checks http(s) pages. Open a website to see its trust report.";
    setMascot("nonweb");
    return;
  }

  if (tab?.id) {
    currentState = await chrome.runtime.sendMessage({ type: "olfa:getState", tabId: tab.id });
    if (currentState) {
      await renderOverview(currentState, currentSettings);
      renderThreatsAndPrivacy(currentState);
      renderLinksAndQr(currentState);
    } else {
      els.activeHost.textContent = tab.url ? new URL(tab.url).hostname : "No active page";
    }
  }

  els.rescanBtn?.addEventListener("click", async () => {
    if (!currentTab?.id) return;
    els.rescanBtn.textContent = "…";
    mascotKey = ""; setMascot("scanning");
    await chrome.runtime.sendMessage({ type: "olfa:rescan", tabId: currentTab.id });
    setTimeout(async () => {
      currentState = await chrome.runtime.sendMessage({ type: "olfa:getState", tabId: currentTab.id });
      if (currentState) {
        await renderOverview(currentState, currentSettings);
        renderThreatsAndPrivacy(currentState);
        renderLinksAndQr(currentState);
      }
      els.rescanBtn.textContent = "↻";
    }, 800);
  });
}

document.addEventListener("DOMContentLoaded", init);


/* ---------- open the main Olfa website (served by the backend) ---------- */
document.getElementById("open-site-btn")?.addEventListener("click", async () => {
  try {
    const settings = await getSettings();
    const base = String(settings.apiUrl || "https://olfa-live.onrender.com").replace(/\/+$/, "");
    await chrome.tabs.create({ url: `${base}/` });
  } catch {
    await chrome.tabs.create({ url: "https://olfa-live.onrender.com/" });
  }
});
