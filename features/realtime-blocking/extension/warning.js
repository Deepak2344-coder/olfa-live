/**
 * Warning page behaviour. Reads the blocked URL, score and reasons from the
 * query string that sw.js built, renders them, and offers the three escapes:
 * go back, trust the site permanently, or proceed once.
 */
(function () {
  'use strict';

  const params = new URLSearchParams(location.search);
  const target = params.get('url') || '';
  const score = Number(params.get('score') || 0);
  let reasons = [];
  try {
    reasons = JSON.parse(params.get('reasons') || '[]');
  } catch (e) {
    reasons = [];
  }

  document.getElementById('hachi').src = chrome.runtime.getURL('assets/hachi.png');
  document.getElementById('target').textContent = target || '(unknown address)';
  document.getElementById('score').textContent =
    'Risk score ' + Math.round(score * 100) + '% — ' + (score > 0.9 ? 'dangerous' : 'suspicious');

  const list = document.getElementById('reasons');
  list.textContent = '';
  if (!reasons.length) {
    const li = document.createElement('li');
    li.textContent = 'This address is on the Olfa blocklist.';
    list.appendChild(li);
  }
  for (const reason of reasons) {
    const li = document.createElement('li');
    li.textContent = reason.message;
    const sev = document.createElement('span');
    sev.className = 'sev ' + (reason.severity || 'medium');
    sev.textContent = reason.severity || 'medium';
    li.appendChild(sev);
    list.appendChild(li);
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return '';
    }
  }

  document.getElementById('back').addEventListener('click', () => {
    if (history.length > 1) history.back();
    else chrome.tabs.update({ url: 'chrome://newtab' });
  });

  document.getElementById('trust').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'olfa:trust', host: hostOf(target) }, () => {
      if (target) location.replace(target);
    });
  });

  document.getElementById('proceed').addEventListener('click', () => {
    if (target) location.replace(target);
  });
})();
