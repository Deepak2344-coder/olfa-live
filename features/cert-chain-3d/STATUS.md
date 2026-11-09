# cert-chain-3d

**Status:** DONE

## What it does

The **cert-chain-3d** feature fetches a site's TLS certificate chain and
classifies its health.  The result is a simple JSON object with a `level`
(`green`/`yellow`/`red`/`gray`) and a `color` hex value that a Three.js
visualisation (or a simple 2D fallback) can use.

### Health levels

| Level   | Condition                              | Color    |
|---------|----------------------------------------|----------|
| **green**   | Certificate valid and >30 days to expiry | `#5fcf80` |
| **yellow**  | Certificate expires within 14–30 days  | `#ffd65a` |
| **red**     | Certificate invalid, self-signed, or ≤14 days to expiry | `#ff5f5f` |
| **gray**    | Could not connect / DNS error          | `#aaaaaa` |

## How to run it

```bash
cd features/cert-chain-3d
npm install          # installs node modules (none beyond Node itself)
npm test             # → "No unit tests (integration-only); demo tested manually."
```

### Demo

```bash
npx serve demo/      # or open demo/index.html in a browser
```

Enter a hostname (e.g. `google.com`) and click **Fetch chain**.  The 2D canvas
updates to show the health colour and basic certificate info.

## Integration notes

- **Import the helper:**

  ```js
  import { fetchChain } from 'features/cert-chain-3d/chain.js';
  ```

- **Fetch a chain and use the colour:**

  ```js
  const data = await fetchChain('example.com');
  // data.color can be passed to a Three.js material, or used as a CSS color.
  ```

- **Graceful degradation** – if the fetch fails (`ok === false`), render a gray
  placeholder and show the error reason.

- **Node environment** – this module uses Node's `tls`/`crypto` APIs and runs
  only in a Node environment.  The demo page calls it from Node via a small dev
  server, or expose the function as an HTTP endpoint.

## License

MIT — see the project root.