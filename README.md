# Olfa core

Detects phishing and malicious websites by fusing four independent checks into one verdict in the shared Olfa risk schema (`score` 0-1, `level`, `reasons[]`, plus a per-check `pillars` breakdown).

| Check | Module | What it looks at |
|---|---|---|
| Threat analysis | `olfa_core/heuristics.py`, `url_model.py`, redirect tracer | Brand impersonation and typosquatting, IP hosts, punycode, risky TLDs, redirect chains, ML URL score |
| Web security assessment | `olfa_core/webcheck.py` | Security headers and cookie flags (graded A-F), cross-origin password forms, hidden iframes, obfuscated script, urgency wording. Page script is never executed |
| Certificate validation | `olfa_core/cert.py` | Trust-store validation with the exact failure reason, hostname match, expiry, self-signed, weak key or hash, old TLS, brand-new certificate, full chain |
| Collaborative intel | `olfa_core/intel.py` | Community reports in SQLite. One vote per reporter per domain, reporter reputation, 45-day decay, and a consensus rule (>= 2 reporters and weighted votes) before a domain counts as "confirmed" |

`olfa_core/fusion.py` combines them with noisy-OR. A pillar that could not run is reported as unavailable, never as clean.

## Run

```bash
pip install -r requirements.txt
python -m uvicorn app:app --port 8790     # UI at http://127.0.0.1:8790/
python -m pytest tests -q                 # 29 tests, no internet needed
```

## API

- `POST /scan {url, deep?: true, lang?: "en"|"hi"|"bn"}` - `deep:false` is a quick scan (no network, ~70 ms) and is what the extension uses.
- `POST /report {url, verdict: phishing|malware|scam|safe, note?}` with header `X-Reporter-Token: <any private random string>`
- `GET /intel/lookup?url=...`, `GET /intel/feed` (confirmed-malicious domains), `GET /health`

## The ML model (olfa-host-v2, retrained)

The shipped model files had a shortcut problem (they scored github.com and example.com as ~98% phishing), so I trained a new one: `models/olfa_host_v2.joblib`, code in `training/`, extractor in `olfa_core/host_features.py` (shipped with the model so training and serving cannot drift). Polarity is always **1 = phishing**.

- **Data:** ~200k current phishing hostnames (Phishing.Database, Nov 2026), ~260k legitimate hosts sampled across the Tranco top-1M (Nov 2026), plus the hostnames from your `urlset.csv` as long-tail legitimate/phishing examples. Scheme, `www.`, port and path are ignored, because those were the shortcuts.
- **Evaluation:** train/test split by registrable domain (no domain appears on both sides). Held-out **AUC 0.91**. At threshold 0.95: 0.25% false alarms (1.4% on small old sites), catches 46% of new phishing hosts. At 0.99: 0.03% false alarms, catches 36%.
- **What that means:** a hostname alone cannot separate most phishing from legitimate sites. 36% of phishing URLs in the feed sit on popular domains (free hosting, compromised sites) and are excluded from training because the host cannot tell them apart; the certificate, page and community checks have to catch those. The model is therefore a *supporting signal*: it counts only when another check also fires, and it is ignored for the Tranco top-100k (`models/top100k_domains.txt`), because brand names inside real hosts (web.whatsapp.com) fool it.
- **Not yet done:** a path-aware model needs modern legitimate URLs *with paths*, which no free feed provides; that is the single biggest accuracy gain left. The service loads portable files (`models/olfa_host_v2_portable/`) and needs only numpy and xgboost; it does not use scikit-learn or pickles at runtime. To retrain, run `training/train_host_model.py` then `training/export_portable.py`.

## Network behaviour (full scan)

- One crawler (`olfa_core/crawl.py`) follows redirects and keeps the final page, so page security reuses it. Every hop connects only to an address Olfa validated itself.
- If your system DNS returns a private address (VPN/proxy fake-IP mode, filtering DNS), Olfa asks a public DNS-over-HTTPS resolver (Cloudflare, then Google) for the real address. All answers must be public, so names that truly point inside a network stay blocked. Disable with `OLFA_DOH=0`.
- `OLFA_ALLOW_CIDRS=198.18.0.0/15` (comma-separated) lets specific ranges through if you know they are safe.
- If a link cannot be reached because of your own network, the result carries a `notes` entry and the check shows as "not checked"; it is never counted against the site.
- `components` in the `/scan` response summarises the four inputs (link model, page security, certificate, community) and the rules used to combine them.

## Security design

- Every fetch goes to an IP Olfa resolved and validated itself (private, loopback, link-local and cloud-metadata addresses are refused), including each redirect hop.
- All page-derived text is rendered with `textContent`, never `innerHTML`.
- Known limits: reporter tokens are anonymous, so a determined attacker can create many; production needs accounts, per-IP limits and moderation. The cache and rate limits are in-process. Hindi and Bengali strings should be reviewed by native speakers.

## Features folder

`features/` is your original ZIP, used as-is except `realtime-blocking/extension/sw.js`, which now sends `deep:false`. Load that folder as an unpacked Chrome extension with the service running on port 8790. Problems found in the ZIP: `multilingual-alerts` Hindi/Bengali strings contain garbled mixed-language text and use reason codes that do not match the shared schema (replaced by `olfa_core/alerts.json`), and the READMEs for `cert-chain-3d` and `brand-matcher` describe Python files that are actually JavaScript.
