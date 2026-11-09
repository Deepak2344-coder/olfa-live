/* Dark mode: follows the saved choice, else the device setting. Loaded in <head> so there is no light flash. */
(function(){
  const KEY = 'olfa-theme', root = document.documentElement;
  const read = () => { try { return localStorage.getItem(KEY); } catch (e) { return null; } };
  const write = v => { try { localStorage.setItem(KEY, v); } catch (e) {} };
  const mq = window.matchMedia ? matchMedia('(prefers-color-scheme: dark)') : null;
  const meta = () => document.querySelector('meta[name="theme-color"]');
  function apply(t){
    root.dataset.theme = t;
    const m = meta(); if (m) m.content = t === 'dark' ? '#1A1411' : '#FFF4E6';
    const b = document.getElementById('themeBtn');
    if (b){ b.setAttribute('aria-pressed', String(t === 'dark')); b.title = t === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'; }
  }
  apply(read() || (mq && mq.matches ? 'dark' : 'light'));
  document.addEventListener('DOMContentLoaded', () => {
    apply(root.dataset.theme);
    const b = document.getElementById('themeBtn');
    if (b) b.addEventListener('click', () => { const n = root.dataset.theme === 'dark' ? 'light' : 'dark'; write(n); apply(n); });
    // keep the active tab visible in the scrolling tab bar on phones
    const nav = document.querySelector('.tabs-nav');
    if (nav) nav.addEventListener('click', e => { const t = e.target.closest('.tab-btn'); if (t && t.scrollIntoView) t.scrollIntoView({inline:'center',block:'nearest',behavior:'smooth'}); });
  });
  if (mq && mq.addEventListener) mq.addEventListener('change', e => { if (!read()) apply(e.matches ? 'dark' : 'light'); });
})();
