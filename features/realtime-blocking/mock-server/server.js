#!/usr/bin/env node
/**
 * Tiny mock scan endpoint for the realtime-blocking demo.
 *
 *   node features/realtime-blocking/mock-server/server.js
 *
 * POST /scan  {url}  -> {url, score, level, reasons[]}
 * GET  /demo/<page>  -> serves ../demo/, so the demo needs no file:// access
 * GET  /health
 *
 * The score is derived from the path, so the demo is deterministic and offline.
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8790);
const DEMO_DIR = path.join(__dirname, '..', 'demo');

function scoreFor(url) {
  const u = String(url || '').toLowerCase();
  if (u.includes('high') || u.includes('paypa1') || u.includes('kyc-update')) return 0.95;
  if (u.includes('medium') || u.includes('lookalike')) return 0.55;
  return 0.05;
}

function reasonsFor(score, url) {
  if (score > 0.9) {
    return [
      {
        code: 'typosquat',
        message: 'The domain imitates a well-known brand but is not that brand.',
        severity: 'high',
        details: { brand: 'paypal', url },
      },
      { code: 'credential_form_cross_origin', message: 'The login form would send your password to another domain.', severity: 'high' },
    ];
  }
  if (score >= 0.4) {
    return [{ code: 'new_domain', message: 'This domain was registered very recently.', severity: 'medium' }];
  }
  return [];
}

function level(score) {
  return score >= 0.75 ? 'dangerous' : score >= 0.4 ? 'suspicious' : 'safe';
}

function cors(res) {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type');
  res.setHeader('access-control-allow-methods', 'POST, GET, OPTIONS');
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png' };

const server = http.createServer((req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true, service: 'olfa-mock-scan' }));
    return;
  }

  if (req.method === 'POST' && req.url === '/scan') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) req.destroy();
    });
    req.on('end', () => {
      let url = '';
      try {
        url = JSON.parse(body || '{}').url || '';
      } catch (e) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'invalid json' }));
        return;
      }
      const score = scoreFor(url);
      const payload = { url, score, level: level(score), reasons: reasonsFor(score, url), source: 'mock' };
      console.log('POST /scan', url, '->', score);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(payload));
    });
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/demo/')) {
    const name = path.basename(req.url.split('?')[0]);
    const file = path.join(DEMO_DIR, name);
    fs.readFile(file, (err, data) => {
      if (err) {
        res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
        return;
      }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' }).end(data);
    });
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' }).end('try /demo/safe.html, /demo/medium.html, /demo/high.html, /demo/popup.html');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Olfa mock scan server on http://127.0.0.1:${PORT}`);
  console.log(`Demo pages: http://127.0.0.1:${PORT}/demo/safe.html`);
});
