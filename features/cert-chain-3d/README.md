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

### API

```js
import { fetchChain } from 'features/cert-chain-3d/chain.js';

const result = await fetchChain('example.com');
// result = {
//   ok: true,
//   host: 'example.com',
//   level: 'green',   // 'green' | 'yellow' | 'red' | 'gray'
//   color: '#5fcf80', // hex color
//   reasons: [ ... ],  // human-readable reasons
//   raw: { subject, issuer, valid_from, valid_to, fingerprint }
// }
```

If `ok` is `false` the connection failed and `level` will be `'gray'`.

### Demo

The demo page (`demo/index.html`) lets you type a hostname and click **Fetch chain**.
The 2D canvas shows the colour and basic info.  (A full Three.js visualisation
would replace the canvas renderer, but the data shape is the same.)

```bash
npx serve demo/      # or open demo/index.html in a browser
```

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
  only in a Node environment (not the browser directly).  The demo page calls it
  from Node via a small dev server, or you can expose the function as an HTTP
  endpoint using your preferred framework.

## Tests

```bash
npm test
# → "No unit tests (integration-only); demo tested manually."
```
The module is exercised end‑to-end by running it against real hosts (e.g.
`fetchChain('google.com')` should return `level: 'green'`).

## License

MIT — see the project root.