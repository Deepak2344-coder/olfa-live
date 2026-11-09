/**
 * Warning page controller.
 * Displays blocked URL, risk score, and detailed reasons.
 * Handles "Go Back", "Trust Domain", and "Proceed Anyway".
 */
(() => {
  'use strict';

  const params = new URLSearchParams(location.search);
  const target = params.get('url') || '';
  const score = Number(params.get('score') || 0);
  let reasons = [];
  try {
    reasons = JSON.parse(params.get('reasons') || '[]');
  } catch {
    reasons = [];
  }

  // Hachi barks once, then stays worried (the page is blocked, so never relax to idle).
  const hachi = document.getElementById('hachi');
  if (hachi) hachi.addEventListener('ended', () => setTimeout(() => hachi.setDog && hachi.setDog('error'), 0));

  const targetEl = document.getElementById('target');
  if (targetEl) targetEl.textContent = target || '(unknown address)';

  const scoreEl = document.getElementById('score');
  const levelEl = document.getElementById('risk-level');
  const isDangerous = score >= 0.75 || params.get('tier') === 'block';

  if (levelEl) {
    levelEl.textContent = isDangerous ? 'Dangerous' : 'Suspicious';
  }
  if (scoreEl) {
    scoreEl.textContent = `Calculated threat risk: ${Math.round(score * 100)}%`;
  }

  const list = document.getElementById('reasons');
  if (list) {
    list.textContent = '';
    if (!reasons.length) {
      const li = document.createElement('li');
      li.textContent = 'This address is flagged as an active phishing or malware distribution vector.';
      list.appendChild(li);
    } else {
      for (const r of reasons) {
        const li = document.createElement('li');
        li.textContent = r.text || r.message || r.code || 'Suspicious site telemetry detected.';
        const sev = document.createElement('span');
        sev.className = 'sev ' + (r.severity || 'medium');
        sev.textContent = r.severity || 'medium';
        li.appendChild(sev);
        list.appendChild(li);
      }
    }
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return '';
    }
  }

  document.getElementById('back')?.addEventListener('click', () => {
    if (history.length > 1) {
      history.back();
    } else {
      chrome.tabs.update({ url: 'chrome://newtab' });
    }
  });

  document.getElementById('trust')?.addEventListener('click', () => {
    const host = hostOf(target);
    if (!host) return;
    chrome.runtime.sendMessage({ type: 'olfa:trustDomain', host }, () => {
      if (target) location.replace(target);
    });
  });

  document.getElementById('proceed')?.addEventListener('click', () => {
    const host = hostOf(target);
    if (!host) return;
    chrome.runtime.sendMessage({ type: 'olfa:allowOnce', host }, () => {
      if (target) location.replace(target);
    });
  });
})();

