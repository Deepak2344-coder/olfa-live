/**
 * Olfa content agent (runs at document_start on every page).
 *
 * Three jobs:
 *   1. Report whether the user actually interacted (navigator.userActivation)
 *      so the service worker knows if a tab may be auto-closed.
 *   2. Draw the medium-tier warning banner when asked.
 *   3. While the banner is up, block form submissions that leave this domain.
 *
 * There are no inline handlers and no remote code: MV3 CSP friendly.
 */
(function () {
  'use strict';

  const BANNER_ID = 'olfa-warning-banner';
  let bannerShown = false;

  function reportActivation() {
    try {
      const activated = Boolean(navigator.userActivation && navigator.userActivation.hasBeenActive);
      chrome.runtime.sendMessage({ type: 'olfa:activation', activated }).catch(() => {});
    } catch (e) {
      /* extension context can be gone after an update */
    }
  }
  reportActivation();
  window.addEventListener('pointerdown', reportActivation, { once: true, capture: true });
  window.addEventListener('keydown', reportActivation, { once: true, capture: true });
  setTimeout(reportActivation, 1500);

  function styles() {
    return `
      #${BANNER_ID} {
        position: fixed; z-index: 2147483647; top: 0; left: 0; right: 0;
        display: flex; gap: 12px; align-items: center;
        padding: 12px 16px; font: 14px/1.4 system-ui, sans-serif;
        background: #fff7e6; color: #3a2c12;
        border-bottom: 2px solid #f0b429; box-shadow: 0 6px 24px rgba(0,0,0,.18);
      }
      #${BANNER_ID} img { width: 40px; height: 40px; flex: 0 0 auto; }
      #${BANNER_ID} .olfa-msg { flex: 1 1 auto; }
      #${BANNER_ID} b { display: block; margin-bottom: 2px; }
      #${BANNER_ID} button {
        font: inherit; border: 1px solid #d9a520; background: #fff; color: #3a2c12;
        border-radius: 8px; padding: 6px 12px; cursor: pointer;
      }
      #${BANNER_ID} button.primary { background: #f0b429; border-color: #f0b429; }
      body { padding-top: 72px !important; }
    `;
  }

  function trustCurrentSite() {
    chrome.runtime.sendMessage({ type: 'olfa:trust', host: location.hostname }).then(() => {
      const el = document.getElementById(BANNER_ID);
      if (el) el.remove();
      bannerShown = false;
    });
  }

  function showBanner(result) {
    if (bannerShown || document.getElementById(BANNER_ID)) return;
    bannerShown = true;

    const style = document.createElement('style');
    style.textContent = styles();
    document.documentElement.appendChild(style);

    const banner = document.createElement('div');
    banner.id = BANNER_ID;

    const img = document.createElement('img');
    img.src = chrome.runtime.getURL('assets/hachi.png');
    img.alt = 'Hachi';
    banner.appendChild(img);

    const msg = document.createElement('div');
    msg.className = 'olfa-msg';
    const title = document.createElement('b');
    title.textContent = 'Hachi is suspicious of this page (' + Math.round(result.score * 100) + '% risk)';
    msg.appendChild(title);
    const detail = document.createElement('span');
    detail.textContent = (result.reasons && result.reasons[0] && result.reasons[0].message) ||
      'This site shows patterns common in phishing pages. Do not enter passwords or card details.';
    msg.appendChild(detail);
    banner.appendChild(msg);

    const trust = document.createElement('button');
    trust.textContent = 'Trust this site';
    trust.addEventListener('click', trustCurrentSite);
    banner.appendChild(trust);

    const leave = document.createElement('button');
    leave.className = 'primary';
    leave.textContent = 'Go back';
    leave.addEventListener('click', () => {
      if (history.length > 1) history.back();
      else location.replace('about:blank');
    });
    banner.appendChild(leave);

    document.documentElement.appendChild(banner);
  }

  /* --- block cross-domain form submits while the banner is up ---------- */
  document.addEventListener(
    'submit',
    (event) => {
      if (!bannerShown) return;
      const form = event.target;
      const action = (form && form.getAttribute && form.getAttribute('action')) || location.href;
      let host = '';
      try {
        host = new URL(action, location.href).hostname;
      } catch (e) {
        return;
      }
      if (host && host !== location.hostname) {
        event.preventDefault();
        event.stopPropagation();
        chrome.runtime.sendMessage({
          type: 'olfa:report',
          url: location.href,
          note: 'blocked cross-domain form submit to ' + host,
        }).catch(() => {});
        alert('Olfa blocked this form: it would send your details to ' + host + '.');
      }
    },
    true
  );

  chrome.runtime.onMessage.addListener((message) => {
    if (message && message.type === 'olfa:show-banner') showBanner(message.result);
  });
})();
