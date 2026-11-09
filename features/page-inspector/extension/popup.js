/**
 * Olfa page-inspector — popup.
 *
 * Gathers three sources and hands them to the pure analyzer:
 *   chrome.cookies        -> cookies (values stripped here, never stored)
 *   background worker     -> requests (already URL/method only)
 *   content script        -> forms, storage keys, fingerprint calls
 *
 * The result uses the shared risk schema, so the core app can consume the same
 * object the popup renders.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  document.getElementById('hachi').src = chrome.runtime.getURL('assets/hachi.png');

  /* ------------------------------- tabs ------------------------------- */
  document.querySelectorAll('nav button').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('nav button').forEach((b) => b.classList.toggle('active', b === button));
      document.querySelectorAll('section').forEach((s) => s.classList.toggle('active', s.id === button.dataset.tab));
    });
  });

  /* --------------------------- data gathering ------------------------- */
  function stripCookie(cookie, pageHost) {
    // Deliberately drop `.value`: the popup shows metadata only.
    const domain = String(cookie.domain || '').replace(/^\./, '');
    return {
      name: cookie.name,
      domain: cookie.domain,
      secure: Boolean(cookie.secure),
      httpOnly: Boolean(cookie.httpOnly),
      sameSite: cookie.sameSite || 'unspecified',
      expires: cookie.expirationDate ? new Date(cookie.expirationDate * 1000).toISOString().slice(0, 10) : 'session',
      thirdParty: Boolean(domain && pageHost && domain !== pageHost && !pageHost.endsWith('.' + domain)),
    };
  }

  function askTab(tabId, message) {
    return new Promise((resolve) => {
      chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) resolve(null); // content script not injected
        else resolve(response);
      });
    });
  }

  /* ------------------------------ render ------------------------------ */
  function cell(text, className) {
    const td = document.createElement('td');
    if (className) td.className = className;
    td.textContent = text;
    return td;
  }

  function renderCookies(cookies, pageHost) {
    const box = $('cookies');
    box.textContent = '';
    if (!cookies.length) {
      box.innerHTML = '<p class="empty">No cookies readable on this page.</p>';
      return;
    }
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Name</th><th>Domain</th><th>Flags</th><th>Expires</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const cookie of cookies) {
      const tr = document.createElement('tr');
      const name = cell(cookie.name);
      if (cookie.thirdParty) name.className = 'third';
      tr.appendChild(name);
      tr.appendChild(cell(cookie.domain, cookie.thirdParty ? 'third' : ''));
      const flags = document.createElement('td');
      const secure = document.createElement('span');
      secure.className = 'flag ' + (cookie.secure ? 'ok' : 'bad');
      secure.textContent = cookie.secure ? 'Secure' : 'insecure';
      const httpOnly = document.createElement('span');
      httpOnly.className = 'flag ' + (cookie.httpOnly ? 'ok' : 'bad');
      httpOnly.textContent = cookie.httpOnly ? 'HttpOnly' : 'JS-readable';
      flags.append(secure, httpOnly);
      const same = document.createElement('span');
      same.className = 'flag ' + (cookie.sameSite === 'unspecified' || cookie.sameSite === 'no_restriction' ? 'bad' : 'ok');
      same.textContent = cookie.sameSite;
      flags.appendChild(same);
      tr.appendChild(flags);
      tr.appendChild(cell(cookie.expires));
      body.appendChild(tr);
    }
    table.appendChild(body);
    box.appendChild(table);
  }

  function renderRequests(requests, pageHost) {
    const box = $('requests');
    box.textContent = '';
    if (!requests.length) {
      box.innerHTML = '<p class="empty">No requests recorded yet — reload the page with the popup closed, then reopen it.</p>';
      return;
    }
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Method</th><th>Host</th><th>Type</th></tr></thead>';
    const body = document.createElement('tbody');
    const seen = new Set();
    for (const request of requests) {
      let host = '';
      try {
        host = new URL(request.url).hostname;
      } catch (e) {
        host = request.url;
      }
      const key = host + '|' + request.method;
      if (seen.has(key)) continue;
      seen.add(key);
      const thirdParty = OlfaInspector.isThirdParty(request.url, pageHost);
      const tr = document.createElement('tr');
      tr.appendChild(cell(request.method.toUpperCase(), request.method === 'POST' ? 'post' : ''));
      tr.appendChild(cell(host, thirdParty ? 'third' : ''));
      tr.appendChild(cell(request.type || ''));
      body.appendChild(tr);
    }
    table.appendChild(body);
    box.appendChild(table);

    const note = document.createElement('p');
    note.className = 'empty';
    note.style.marginTop = '8px';
    note.textContent = 'Orange = another domain. Red = data sent (POST).';
    box.appendChild(note);
  }

  function renderForms(facts, result) {
    const box = $('forms');
    box.textContent = '';
    const forms = facts ? facts.forms || [] : [];
    if (!forms.length) {
      box.innerHTML = '<p class="empty">No forms on this page.</p>';
    } else {
      const table = document.createElement('table');
      table.innerHTML = '<thead><tr><th>Action</th><th>Fields</th><th>Risk</th></tr></thead>';
      const body = document.createElement('tbody');
      for (const form of forms) {
        const tr = document.createElement('tr');
        const action = cell(form.action || '(same page)');
        tr.appendChild(action);
        const secret = (form.fields || []).filter((f) => OlfaInspector.looksLikePassword(f) || OlfaInspector.looksLikeCard(f));
        tr.appendChild(cell(secret.map((f) => f.name || f.type).join(', ') || 'no password/card fields'));
        let risky = '';
        try {
          const actionHost = new URL(form.action || facts.pageUrl).hostname;
          const pageHost = new URL(facts.pageUrl).hostname;
          if (secret.length && actionHost !== pageHost) risky = 'cross-origin secret';
          else if (secret.length && (form.action || '').startsWith('http:')) risky = 'http';
        } catch (e) {
          risky = '';
        }
        tr.appendChild(cell(risky, risky ? 'post' : ''));
        body.appendChild(tr);
      }
      table.appendChild(body);
      box.appendChild(table);
    }

    if (result.reasons.length) {
      const heading = document.createElement('p');
      heading.style.margin = '12px 0 4px';
      heading.style.fontWeight = '600';
      heading.textContent = 'Why this page is suspicious';
      box.appendChild(heading);
      const list = document.createElement('ul');
      list.className = 'reasons';
      for (const reason of result.reasons) {
        const li = document.createElement('li');
        li.textContent = reason.message;
        list.appendChild(li);
      }
      box.appendChild(list);
    }
  }

  function renderStorage(facts) {
    const box = $('storage');
    box.textContent = '';
    const storage = (facts && facts.storageKeys) || { local: [], session: [] };
    const calls = (facts && facts.fingerprintCalls) || [];

    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Store</th><th>Keys</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const [store, keys] of [['localStorage', storage.local], ['sessionStorage', storage.session]]) {
      const tr = document.createElement('tr');
      tr.appendChild(cell(store));
      tr.appendChild(cell(keys.length ? keys.join(', ') : '—'));
      body.appendChild(tr);
    }
    table.appendChild(body);
    box.appendChild(table);

    const heading = document.createElement('p');
    heading.style.margin = '12px 0 4px';
    heading.style.fontWeight = '600';
    heading.textContent = 'Device fingerprinting';
    box.appendChild(heading);
    const p = document.createElement('p');
    p.className = calls.length ? '' : 'empty';
    p.textContent = calls.length
      ? `This page called: ${Array.from(new Set(calls)).join(', ')} — these read device characteristics that survive clearing cookies.`
      : 'No canvas, audio or permission fingerprinting calls seen since this page loaded.';
    box.appendChild(p);
  }

  /* ------------------------------ boot -------------------------------- */
  async function main() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !/^https?:/i.test(tab.url || '')) {
      $('host').textContent = 'Not a web page';
      $('summary').textContent = 'Open an http(s) page to inspect it.';
      return;
    }

    let pageHost = '';
    try {
      pageHost = new URL(tab.url).hostname;
    } catch (e) {
      pageHost = '';
    }
    $('host').textContent = pageHost;

    const [cookies, requestResponse, factsResponse] = await Promise.all([
      new Promise((resolve) => chrome.cookies.getAll({ url: tab.url }, (list) => resolve(list || []))),
      chrome.runtime.sendMessage({ type: 'olfa:get-requests', tabId: tab.id }).catch(() => ({ requests: [] })),
      askTab(tab.id, { type: 'olfa:inspect' }),
    ]);

    const strippedCookies = cookies.map((c) => stripCookie(c, pageHost));
    const facts = {
      pageUrl: tab.url,
      cookies: strippedCookies,
      requests: (requestResponse && requestResponse.requests) || [],
      forms: (factsResponse && factsResponse.forms) || [],
      storageKeys: (factsResponse && factsResponse.storageKeys) || { local: [], session: [] },
      fingerprintCalls: (factsResponse && factsResponse.fingerprintCalls) || [],
    };

    const { result, signals } = OlfaInspector.analyze(facts);

    $('score').textContent = Math.round(result.score * 100) + '%';
    $('score').className = 'score ' + result.level;
    const counts = [];
    if (facts.cookies.length) counts.push(`${facts.cookies.length} cookies`);
    if (facts.requests.length) counts.push(`${facts.requests.length} requests`);
    if (facts.forms.length) counts.push(`${facts.forms.length} forms`);
    $('summary').textContent = counts.join(' · ') || 'nothing collected yet';

    renderCookies(strippedCookies, pageHost);
    renderRequests(facts.requests, pageHost);
    renderForms(factsResponse, result);
    renderStorage(factsResponse);

    // Handy for the core app: the exact risk object this page produced.
    window.__olfaResult = result;
    window.__olfaSignals = signals;
  }

  main();
})();
