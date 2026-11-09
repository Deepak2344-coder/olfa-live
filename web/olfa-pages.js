/* Extension tab (download info, copy buttons) + #hash tab links */
(function(){
  const $ = id => document.getElementById(id);
  fetch('/download/extension-info').then(r => r.json()).then(i => {
    if (!i.available) { $('extMeta').textContent = 'Not installed on this server'; $('extBtn').style.display = 'none'; return; }
    $('extMeta').textContent = 'Version ' + i.version + ' · Chrome / Edge / Brave';
  }).catch(() => { $('extMeta').textContent = ''; });
  document.querySelectorAll('.pg-copy').forEach(b => b.addEventListener('click', () => {
    const t = b.dataset.copy; (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(() => {
      b.textContent = 'Copied!'; setTimeout(() => b.textContent = 'Copy', 1400);
    }).catch(() => { b.textContent = t; });
  }));
  const open = name => { const b = document.querySelector('.tab-btn[data-tab="' + name + '"]'); if (b) b.click(); };
  const fromHash = () => { const h = location.hash.slice(1); if (h === 'about' || h === 'extension') open(h); };
  fromHash(); window.addEventListener('hashchange', fromHash);
  const p = location.pathname.replace(/\/+$/, '');
  if (p === '/about') open('about'); else if (p === '/extension') open('extension');
  document.querySelectorAll('[data-goto]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); open(a.dataset.goto); }));
})();
