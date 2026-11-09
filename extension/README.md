# Olfa Master Extension (Manifest V3)

Unified AI Threat Shield, Real-Time Navigation Interceptor, Pop-up Ad Blocker, QR Quishing Detector, and Trust Nutrition Label extension for Chromium browsers.

Mascot: **Hachi** (The Shiba Inu).

---

## 🚀 What It Does

| Capability | Where It Lives | Notes |
|---|---|---|
| **Real-Time Navigation Blocker** | `background.js` + `warning.html` | Stops users before visiting confirmed phishing, malware, or brand typosquats; offers "Go Back", "Trust Domain", or "Proceed Once". |
| **Smart Pop-up & Ad Blocker** | `lib/adblock.js` + `rules.json` + `background.js` | Closes unsolicited popup windows/tabs spawned by shady ad networks and neutralizes transparent full-screen clickjacking overlays. |
| **Offline Fast URL Triage** | `lib/triage.js` | Zero-latency evaluation (<5ms) using typosquatting checks (16+ top brands), IP literal checks, punycode, and regex rules. Works when completely offline. |
| **Olfa Core ML Link Analysis** | `lib/api.js` → `POST https://olfa-live.onrender.com/scan` | Evaluates URL character patterns against the retrained portable model (`olfa_host_v2_portable` XGBoost/LogReg) + Lexical rules. Cached 10 min. |
| **Live TLS Certificate Inspection** | `improvedML/olfa_core/cert.py` via `api.js` | Connects via raw SSL socket to inspect the true TLS certificate chain (`host -> intermediate -> root CA`), validity days left, and cipher. |
| **Domain Registration Age** | `improvedML/olfa_core/domainage.py` | Flags burner domains registered only a few days ago via RDAP. |
| **In-Page Active Threat Detection** | `content/agent.js` + `lib/threats.js` | Finds hidden `<iframe>`s, clickjacking overlays, high-entropy obfuscated scripts, and clipboard/keystroke abuse. |
| **Page Privacy & Data Sharing** | `content/agent.js` + `lib/signals.js` | Discovers tracker hosts, cross-origin credential forms, and insecure cookies (strictly dropping cookie values). |
| **On-Page Links & QR Quishing Scan** | `content/agent.js` + `vendor/jsQR.js` + `lib/qr.js` | Decodes QR images in-page via jsQR, checks destination links against the API, and highlights dangerous targets in red (`qr-unsafe`) and amber (`qr-suspicious`). |
| **Interactive Trust Card & Letter Grade** | `lib/grade.js` + `popup/` | Computes security letter grades ($A$ through $F$) based on SSL, domain age, security headers, and threats. |
| **Multilingual Scam Message Checker** | `lib/message.js` + `popup/` | Paste SMS, WhatsApp, or email text; highlights urgency patterns, fake OTP requests, and scam spans in **English, Hindi, and Bengali**. |
| **Community Intel & Reporting** | `lib/api.js` + `olfa_intel.db` | 1-click submission of phishing reports or safe confirmations updating the shared SQLite intelligence feed. |

---

## 🛠️ How to Load Unpacked in Chrome

1. Start the **Olfa Core API server** from the repo root:
   ```bash
   python -m uvicorn improvedML.app:app --port 8790 --host 127.0.0.1
   ```
2. Open Chrome and navigate to:
   ```text
   chrome://extensions/
   ```
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the `master-extension` directory (`master-extension`).
5. Pin the **Olfa Shield** extension icon in your Chrome toolbar.

---

## 🧪 Running Unit Tests

The test suite runs with Node's native test runner without any external network or mock dependencies:

```bash
cd master-extension
npm test
```
All **94 unit tests** cover:
- Ad & pop-up blocker URL patterns and overlay detection (`adblock.test.mjs`)
- Instant offline triage and typosquatting heuristics (`triage.test.mjs`)
- Privacy signals, form checks, and tracker detection (`signals.test.mjs`)
- Clickjacking and obfuscated script detection (`threats.test.mjs`)
- QR decoding and link target classification (`qr.test.mjs`)
- Trust nutrition grade calculation (`grade.test.mjs`)
- Multilingual translations in EN, HI, BN (`alerts.test.mjs`)
- Scam message text analyzer (`message.test.mjs`)
- Schema normalization and API pipeline (`normalize.test.mjs`, `pipeline.test.mjs`)

---

## 📂 Layout

```text
master-extension/
├── manifest.json            # Manifest V3 (declarative permissions, DNR rules, content scripts)
├── background.js            # Unified Service Worker (navigation triage, interceptor, popup closer)
├── rules.json               # Declarative Net Request rules for blocking ad popups & known malicious hosts
├── warning.html / warning.js# Real-time full-screen blocking interstitial
├── popup.html / popup.css   # 5-tab modern popup UI (Overview, In-Page, Links/QR, Message, Report)
├── popup.js                 # Popup controller & state management
├── options.html / options.js# Settings (API Endpoint, Pop-up Shield toggle, Cookie permission grant)
├── lib/
│   ├── adblock.js           # Ad & popup detector, overlay classifier
│   ├── api.js               # API client for /scan and /report with 10-min cache
│   ├── triage.js            # Offline URL heuristics, typosquatting (16+ brands) & blocklist
│   ├── signals.js           # Privacy, cookie hygiene, forms & resource analysis
│   ├── threats.js           # Clickjacking, script entropy & DOM threat rules
│   ├── qr.js                # Link categorization & QR target parsing
│   ├── grade.js             # Nutrition trust score calculation (A-F grading)
│   ├── alerts.js            # Multilingual copy engine (EN, HI, BN)
│   ├── message.js           # Scam message text parser with regex spans
│   ├── normalize.js         # Schema bridge between backend risk and local findings
│   └── logic.js             # Badge color mapping, cache expiration & bounded mapLimit
├── content/
│   ├── fingerprint.js       # Injected in MAIN world at document_start (API monitors)
│   ├── agent.js             # Injected in ISOLATED world at document_idle (DOM facts, threats, QR)
│   ├── banner.js / css      # In-page warning banner
│   └── style.css            # QR/link highlight classes (qr-unsafe, qr-suspicious)
├── vendor/
│   └── jsQR.js              # Lightweight QR decoder (v1.4.0)
├── assets/
│   └── hachi.png            # Hachi mascot icon
└── tests/                   # 94 Node native test suites (node --test)
```

