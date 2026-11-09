# realtime-blocking — Olfa protects you while you browse

A Chrome (Manifest V3) extension that checks every page **before it renders** and
reacts in three tiers. Hachi does the watching.

| Verdict | When | What the user sees |
| --- | --- | --- |
| **block** | blocklisted host, or score > 0.9 | Full-screen warning page, loaded instead of the site |
| **warn** | 0.4 ≤ score ≤ 0.9 | Orange banner + cross-domain form submissions blocked |
| **log** | score < 0.4 | Nothing visible, nothing logged |

## How it decides

1. **Local, always** (`extension/lib/tier.js`, no network): bundled blocklist,
   typosquat distance against 16 top brands, and URL heuristics (http, raw IP,
   punycode, suspicious TLD, subdomain stacking, lure keywords, hyphen chains).
2. **Backend, only when inconclusive** — if the local verdict is `log`, it calls
   the configured `backendUrl` (`POST /scan`, shared risk schema) with a 1.5 s
   timeout. Offline? The local verdict stands; nothing breaks.
3. **declarativeNetRequest** (`extension/rules.json`) hard-blocks the bundled
   blocklist before a request is even made. The friendly warning page comes from
   the `webNavigation` layer, which still runs before paint.

## Popup auto-close (and why it is safe)

A tab is only closed when **all** of these hold:

- it was opened by a page (`openerTabId` is set — user-opened tabs never qualify),
- the page inside it never received a gesture (`navigator.userActivation`, reported
  by the content script at `document_start`; if no report arrives within 1.5 s the
  tab counts as unattended),
- the URL scored in the block tier,
- and the "close risky tabs that opened themselves" setting is on.

Closing shows a notification with an **Undo** button that reopens the URL as a
normal user-owned tab (so it will not be closed again).

## Safeguards

- **Whitelist**: `gov.in`, `nic.in`, `edu`, `ac.in`, `edu.in`, and the official
  domains of the tracked brands are never blocked, whatever the heuristics say.
- **Trust this site** button on the banner and warning page → adds the host to a
  persistent trusted list (`options.html` can remove entries).
- **Settings toggle** for auto-close, and an optional scan endpoint field.
- **Log page** (same `options.html`): every blocked/warned/closed URL with score
  and a *Report false positive* button.
- **Proceed anyway** on the warning page for one visit.

## Run the demo

```bash
# 1. mock scan endpoint + demo pages (no dependencies)
node features/realtime-blocking/mock-server/server.js

# 2. in Chrome: chrome://extensions → Developer mode → Load unpacked →
#    select features/realtime-blocking/extension

# 3. open the four demo pages
#    http://127.0.0.1:8790/demo/safe.html    -> silent
#    http://127.0.0.1:8790/demo/medium.html  -> banner + form blocked
#    http://127.0.0.1:8790/demo/high.html    -> full-screen warning
#    http://127.0.0.1:8790/demo/popup.html   -> tab closed + Undo notification
```

Click the toolbar icon (or *Extension options*) for settings and the log.

## Tests

```bash
node --test features/realtime-blocking/tests/tier.test.js   # 11 tests, no browser needed
```

The tests cover the tier boundaries (`0.9` / `0.4`), the whitelist overrides,
blocklist matching, typosquat true/false positives (`paypa1.com` yes,
`paypal.com` no, brand-as-subdomain yes), each heuristic, and that every emitted
reason satisfies the shared schema.

## Integrating into the core app

Two ways, depending on what the core app needs:

1. **As an extension** — it is standalone; ship the folder as is. It talks to the
   backend through `POST /scan` (`{url}` → shared risk schema), configurable in
   the options page.
2. **Reuse the logic** — `extension/lib/tier.js` is dependency-free and exposes
   `localCheck(url)` and `decideTier(score, {blocklisted, whitelisted})`. The core
   backend can `require()` it directly to pre-score URLs without Chrome.

```js
const { localCheck } = require('./features/realtime-blocking/extension/lib/tier.js');
const { result, tier } = localCheck('http://paypa1-login.example/verify');
// result: shared schema object, tier: 'block' | 'warn' | 'log' | 'allow'
```

## Known limits

- The blocklist and brand list are small demo corpora, not a threat feed.
- Typosquat detection is edit distance ≤ 2 on the second-level label; it will
  miss homoglyphs outside punycode and is deliberately quiet on 1-letter TLD
  tricks (`paypa1.co` vs `paypal.co` is caught, `paypaI.com` may not be).
- `webNavigation` redirects after the request starts; DNR covers the blocklist
  case at request time, but a backend-only block still loads a few KB first.
- No tab-level "allow once" persistence: *Proceed anyway* is per navigation.
