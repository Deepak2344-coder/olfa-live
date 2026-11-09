#!/usr/bin/env node
/**
 * Demo server for page-inspector.
 *
 *   node features/page-inspector/demo/server.js
 *   -> open http://127.0.0.1:8791/
 *
 * Serving on 127.0.0.1 while the page references localhost:8791 gives us a
 * genuine third-party origin (different hostname) without any real network.
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8791);
const HERE = __dirname;

const TRACKER_JS = `
/* Pretend third-party tracker: drops a cookie on its own domain. */
(function () {
  document.cookie = 'tracker_id=t-987; path=/; SameSite=None; Secure';
  console.log('[demo-tracker] loaded from', location.origin, '->', document.currentScript && document.currentScript.src);
})();
`;

function cors(res) {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type');
  res.setHeader('access-control-allow-methods', 'POST, GET, OPTIONS');
  res.setHeader('access-control-allow-credentials', 'true');
}

const server = http.createServer((req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.writeHead(204).end();

  if (req.url === '/' || req.url === '/index.html') {
    const html = fs.readFileSync(path.join(HERE, 'index.html'));
    return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(html);
  }

  if (req.url === '/tracker.js') {
    return res.writeHead(200, { 'content-type': 'text/javascript' }).end(TRACKER_JS);
  }

  if (req.method === 'POST' && (req.url === '/beacon' || req.url === '/steal')) {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      console.log('POST', req.url, body.slice(0, 200));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true, received: body.length }));
    });
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`page-inspector demo on http://127.0.0.1:${PORT}/`);
  console.log(`tracker origin:  http://localhost:${PORT}/tracker.js`);
});
