// Runs inside the floating mascot frame (an extension page, isolated from the website).
import "./lib/hachi-dog.js";
import { sendReport } from "./lib/api.js";

const dog = document.getElementById("dog"), tilt = document.getElementById("tilt");
const bubble = document.getElementById("bubble"), bt = document.getElementById("bt"), bs = document.getElementById("bs");
const panel = document.getElementById("panel");
let info = { url: "", verdict: "scanning", score: null, reasons: [] };
const post = (m) => parent.postMessage({ olfa: true, ...m }, "*");

const POSES = {
  idle:       { dog: "idle",     rest: "idle" },
  scanning:   { dog: "scanning", rest: "scanning" },
  safe:       { dog: "safe",     rest: "idle" },
  suspicious: { dog: "error",    rest: "error" },
  dangerous:  { dog: "phishing", rest: "error" },
  pet:        { dog: "safe",     rest: null },
  nap:        { dog: "offline",  rest: "offline" },
};
let rest = "scanning", restKey = "scanning", bubbleTimer = 0;

dog.addEventListener("ended", () => setTimeout(() => dog.setDog(rest), 0));

function showBubble(title, sub, mood, ttl) {
  clearTimeout(bubbleTimer);
  if (title && !panel.hidden) return;
  if (!title) { bubble.hidden = true; post({ size: "compact" }); return; }
  bt.textContent = title; bs.textContent = sub || ""; bs.hidden = !sub;
  bubble.dataset.mood = mood || ""; bubble.hidden = false;
  post({ size: "wide" });
  if (ttl) bubbleTimer = setTimeout(() => showBubble(null), ttl);
}

const LABEL = { safe: "Looks safe", suspicious: "Be careful here", dangerous: "Dangerous page", scanning: "Still checking…" };
function openPanel() {
  clearTimeout(bubbleTimer); bubble.hidden = true; panel.hidden = false; document.getElementById("pf").textContent = "";
  document.querySelectorAll(".pb button").forEach((b) => (b.disabled = false));
  document.getElementById("pv").textContent = LABEL[info.verdict] || "Report" + (info.score != null ? " · " + info.score + "/100" : "");
  if (info.score != null && info.verdict !== "scanning") document.getElementById("pv").textContent += " · " + info.score + "/100";
  document.getElementById("pu").textContent = info.url;
  const ul = document.getElementById("pr"); ul.textContent = "";
  const rs = info.reasons.length ? info.reasons : [{ text: info.verdict === "safe" ? "No warning signs found." : "No details yet." }];
  for (const r of rs) { const li = document.createElement("li"); li.textContent = r.text; ul.appendChild(li); }
  post({ size: "panel" });
}
function closePanel() { panel.hidden = true; post({ size: bubble.hidden ? "compact" : "wide" }); }
document.getElementById("px").addEventListener("click", closePanel);
document.getElementById("rep").addEventListener("click", () => (panel.hidden ? openPanel() : closePanel()));
bubble.addEventListener("click", (e) => { if (e.target.id !== "bx") openPanel(); });
document.querySelector(".pb").addEventListener("click", async (e) => {
  const v = e.target.dataset && e.target.dataset.v;
  if (!v) return;
  document.querySelectorAll(".pb button").forEach((b) => (b.disabled = true));
  const pf = document.getElementById("pf");
  try {
    await sendReport({ url: info.url, verdict: v });
    pf.textContent = v === "safe" ? "Thanks! Marked as safe." : "Thanks! Reported to the community.";
    dog.setDog(v === "safe" ? "safe" : "blocked"); // blocked = paw stamp
  } catch (err) {
    pf.style.color = "#B23A30"; pf.textContent = "Saved locally. Server unreachable.";
    dog.setDog("error");
  }
});

function apply(msg) {
  if (msg.info) info = msg.info;
  const p = POSES[msg.pose];
  if (!p) return;
  if (msg.pose !== "pet") { rest = p.rest; restKey = msg.pose; }
  dog.setDog(p.dog);
  showBubble(msg.title, msg.sub, msg.mood, msg.ttl);
  if (msg.pose === "pet" ) rest = POSES[restKey].rest; // after a pet, go back to the page's mood
}

window.addEventListener("message", (e) => {
  if (e.source !== parent) return;
  const d = e.data;
  if (!d || d.olfa !== true) return;
  if (d.cfg) { document.documentElement.style.setProperty("--dg", d.cfg.dogSize + "px"); dog.style.setProperty("--hachi-size", d.cfg.dogSize + "px"); tilt.style.width = tilt.style.height = d.cfg.dogSize + 24 + "px"; }
  if (d.pose) apply(d);
  if (d.look) { // cursor position relative to the frame centre, -1..1: gentle 3D parallax
    dog.style.setProperty("--ry", (d.look.x * 9).toFixed(1) + "deg");
    dog.style.setProperty("--rx", (-d.look.y * 6).toFixed(1) + "deg");
  }
});

document.getElementById("bx").addEventListener("click", () => showBubble(null));
document.getElementById("min").addEventListener("click", () => post({ nap: true }));

/* drag to move; a click without moving pets Hachi */
let down = null, moved = false;
tilt.addEventListener("pointerdown", (e) => { down = { x: e.screenX, y: e.screenY }; moved = false; tilt.setPointerCapture(e.pointerId); });
tilt.addEventListener("pointermove", (e) => {
  if (!down) return;
  const dx = e.screenX - down.x, dy = e.screenY - down.y;
  if (!moved && Math.hypot(dx, dy) < 4) return;
  if (!moved) { moved = true; tilt.classList.add("dragging"); }
  down = { x: e.screenX, y: e.screenY };
  post({ drag: { dx, dy } });
});
tilt.addEventListener("pointerup", () => {
  if (!down) return;
  tilt.classList.remove("dragging");
  if (!moved) post({ pet: true }); else post({ dropped: true });
  down = null;
});
post({ ready: true });
