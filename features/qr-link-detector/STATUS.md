# qr-link-detector

**Status:** DONE

## What it is

A Chrome MV3 extension that scans every page for QR code candidates and
redirect/shortened links, displaying results in the popup.

## Detection Capabilities

| Feature | Method | Severity |
|---|---|---|
| QR code candidates | Heuristic scan of `<img>`/`<canvas>` elements | low |
| Known URL shorteners | Hard‑coded list: bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, short.link, is.gd, buff.ly, rebrandly.com, bit.do | medium |
| Tracking parameters | UTM (`utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`), `gclid`, `fbclid`, `mc_campaign`, `mc_id` | low |

## Popup UI

- **QR Codes** count + description + source (first 80 chars of `src`)
- **Redirect/Shortened Links** list with: display URL (truncated), severity badge, domain, tracking params
- **Status bar**: total counts + overall severity

## How to Install

```bash
chrome://extensions/ → Enable Developer mode → Load unpacked → 
  features/qr-link-detector/extension/
```

## Node Tests

```bash
node --test features/qr-link-detector/tests/detect-test.js
# → 8/8 pass, 0 fail
# (verifies file structure + JSON manifest validity)
```