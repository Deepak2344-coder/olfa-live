# redirect-tracer — where does that link really go?

A small FastAPI service plus a timeline UI that follows a URL's whole redirect
chain and says what it thinks of it.

## What it does

`POST /trace {"url": "https://bit.ly/xyz"}` walks the chain and returns one
object: the shared risk score/reasons **plus** the full hop list.

Followed redirect kinds:

- HTTP `3xx` with a `Location` header (up to 10 hops)
- `<meta http-equiv="refresh" content="0; url=...">`
- literal `window.location = "..."` / `location.href = "..."` assignments,
  extracted **as text** — page JavaScript is never executed

### Per hop

| Field | Meaning |
| --- | --- |
| `url` | the address at this step |
| `status` | HTTP status (null for markup/blocked steps) |
| `domain` | hostname |
| `kind` | `http`, `meta_refresh`, `js`, `blocked`, `loop` |
| `shortener` | domain is in `shorteners.json` |
| `domain_changed` | differs from the previous hop |
| `elapsed_ms` | time that hop took |
| `error` | set when the hop failed or was refused |

### Flags → reasons

| Flag | Reason code | Severity |
| --- | --- | --- |
| more than 10 hops | `too_many_hops` | medium |
| a shortener was used | `shortener_used` | low |
| chain crosses several domains | `domain_hopping` | medium |
| final domain ≠ starting domain | `final_domain_differs_from_origin` | medium |
| https → http | `https_downgrade` | high |
| revisits a URL | `redirect_loop` | high |
| hop points at a private/local address | `blocked_private_address` | high |
| a hop could not be fetched | `fetch_failed` | low |

## SSRF protection

Before every hop:

- scheme must be `http` or `https` (`file:`, `gopher:`… are refused),
- the host is resolved and **any** private, loopback, link-local, reserved,
  multicast or unspecified address is refused — this covers `127.0.0.1`,
  `10/8`, `192.168/16`, `169.254.169.254` (cloud metadata) and friends,
- DNS failures are reported, not retried,
- a blocked hop ends the trace and is recorded with `kind: "blocked"`.

`allow_private=True` / `allow_hosts=[...]` exist for the test suite only; the
HTTP API never passes them, so a public deployment cannot be pointed at your
intranet.

## Run it

```bash
pip install -r features/redirect-tracer/requirements.txt
python -m uvicorn app:app --app-dir features/redirect-tracer --port 8788
# open http://127.0.0.1:8788/
```

Or `python features/redirect-tracer/app.py` (same thing, port 8788).

## Tests

```bash
python -m pytest features/redirect-tracer/tests -q      # 11 passed
```

They spin up a local mock server with a header-redirect chain ending in a meta
refresh, a JS `location` page, a two-step loop, a 12-hop chain and a redirect to
`http://10.0.0.1`. The private-IP case asserts the hop was recorded as blocked
and never fetched. Flag rules are also tested directly as pure functions.

## Integrating into the core app

Two options:

1. **HTTP**: `POST /trace` returns the shared schema with `hops`, `flags` and
   `final_url` added. The core backend can proxy it, or call
   `features.redirect_tracer.tracer.trace()` directly.
2. **Import**: `from tracer import trace` (after adding the folder to
   `sys.path`) — `trace()` never raises; failures land in `result.error` and the
   matching flag.

## Known limits

- JS redirects are matched with a conservative regex; obfuscated redirects
  (`atob`, `eval`, string concatenation) are missed by design — we do not run
  page code.
- Response bodies are read up to 200 KB; a redirect later in a huge page is
  missed.
- The shortener list is bundled and hand-checked, not a live feed.
- No cookies, no JS challenges, no Cloudflare-style interstitials: a chain may
  end early on a page that only renders in a browser.
