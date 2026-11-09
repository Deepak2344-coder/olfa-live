/**
 * Settings + log page. Pure chrome.storage, no build step.
 */
(function () {
  'use strict';
  const DEFAULTS = { autoClose: true, backendUrl: 'http://127.0.0.1:8790/scan', trusted: [], log: [] };

  const $ = (id) => document.getElementById(id);

  function toast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 1800);
  }

  function render(state) {
    $('autoClose').checked = Boolean(state.autoClose);
    $('backendUrl').value = state.backendUrl || '';

    const trusted = $('trusted');
    trusted.textContent = '';
    (state.trusted || []).forEach((host) => {
      const li = document.createElement('li');
      const name = document.createElement('span');
      name.textContent = host;
      const remove = document.createElement('button');
      remove.textContent = 'Remove';
      remove.addEventListener('click', async () => {
        const current = await chrome.storage.local.get(DEFAULTS);
        await chrome.storage.local.set({ trusted: current.trusted.filter((h) => h !== host) });
        refresh();
      });
      li.append(name, remove);
      trusted.appendChild(li);
    });

    const rows = $('logRows');
    rows.textContent = '';
    const log = state.log || [];
    $('emptyLog').style.display = log.length ? 'none' : 'block';
    log.forEach((entry) => {
      const tr = document.createElement('tr');

      const when = document.createElement('td');
      when.textContent = new Date(entry.at).toLocaleTimeString();
      tr.appendChild(when);

      const kind = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = 'kind ' + entry.kind;
      badge.textContent = entry.kind;
      kind.appendChild(badge);
      tr.appendChild(kind);

      const url = document.createElement('td');
      url.textContent = entry.url;
      url.style.wordBreak = 'break-all';
      tr.appendChild(url);

      const score = document.createElement('td');
      score.textContent = typeof entry.score === 'number' ? Math.round(entry.score * 100) + '%' : '—';
      tr.appendChild(score);

      const actions = document.createElement('td');
      const report = document.createElement('button');
      report.textContent = 'Report false positive';
      report.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'olfa:report', url: entry.url, note: 'from log page' }, () => {
          report.textContent = 'Reported ✓';
          report.disabled = true;
          toast('Thanks — logged for review.');
        });
      });
      actions.appendChild(report);
      tr.appendChild(actions);

      rows.appendChild(tr);
    });
  }

  async function refresh() {
    const state = await chrome.storage.local.get(DEFAULTS);
    render({ ...DEFAULTS, ...state });
  }

  $('autoClose').addEventListener('change', async (event) => {
    await chrome.storage.local.set({ autoClose: event.target.checked });
    toast(event.target.checked ? 'Auto-close on' : 'Auto-close off');
  });

  $('backendUrl').addEventListener('change', async (event) => {
    await chrome.storage.local.set({ backendUrl: event.target.value.trim() });
    toast('Scan endpoint saved');
  });

  $('addTrust').addEventListener('click', async () => {
    const host = $('trustInput').value.trim().toLowerCase();
    if (!host) return;
    const state = await chrome.storage.local.get(DEFAULTS);
    await chrome.storage.local.set({ trusted: Array.from(new Set([...(state.trusted || []), host])) });
    $('trustInput').value = '';
    toast('Trusted ' + host);
    refresh();
  });

  $('clearLog').addEventListener('click', async () => {
    await chrome.storage.local.set({ log: [] });
    toast('Log cleared');
    refresh();
  });

  refresh();
})();
