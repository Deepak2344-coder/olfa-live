// ============================================================
// Olfa service connection
// Same origin when this file is served by improvedML (port 8790).
// Opening the file directly falls back to that local service.
// Score stays 0–1, the same scale the model returns. The page never re-scores it.
// ============================================================
const API_BASE = location.protocol === 'file:' ? 'http://127.0.0.1:8790' : '';
const PILLAR_LABEL = {threat:'Link', web:'Page', certificate:'Certificate', intel:'Community'};
let lastScan = null;

function reporterToken(){
  let token = store.get('reporter', '');
  if (!token || String(token).length < 8) {
    token = (crypto.randomUUID && crypto.randomUUID()) || ('olfa-' + Date.now().toString(36) + Math.random().toString(36).slice(2));
    store.set('reporter', token);
  }
  return token;
}
function currentLang(){ return ($('#langSelect') && $('#langSelect').value) || 'en'; }

async function api(path, options){
  let response;
  try {
    response = await fetch(API_BASE + path, options);
  } catch (e) {
    throw new Error('Olfa is not reachable. Start it with: python -m uvicorn app:app --port 8790');
  }
  let body = null;
  try { body = await response.json(); } catch (e) { body = null; }
  if (!response.ok) {
    const detail = body && (body.detail || body.message);
    throw new Error(typeof detail === 'string' ? detail : ('The service answered ' + response.status));
  }
  return body;
}

function viewFromScan(data, requested){
  const score = typeof data.score === 'number' ? data.score : 0;
  const level = data.level || (score >= 0.75 ? 'dangerous' : score >= 0.4 ? 'suspicious' : 'safe');
  let host = requested;
  try { host = new URL(data.final_url || data.url || requested).hostname; } catch (e) {}
  return {
    verdict: level,
    score: score,
    reasons: Array.isArray(data.reasons) ? data.reasons : [],
    host: host,
    href: data.url || requested,
    finalUrl: data.final_url || data.url || requested,
    deep: !!data.deep,
    elapsed: data.elapsed_ms,
    pillars: data.pillars || {},
    components: data.components || null,
    intel: data.intel || null,
    notes: data.notes || [],
    raw: data
  };
}

async function scanUrl(url, deep){
  if (deep == null) deep = !$('#deepScan') || $('#deepScan').checked;
  const data = await api('/scan', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({url: url, deep: deep, lang: currentLang()})
  });
  return viewFromScan(data, url);
}

function rememberScan(view){
  const rows = store.get('scans', []);
  rows.unshift({url: view.href, host: view.host, level: view.verdict, score: view.score, at: Date.now(), deep: view.deep});
  store.set('scans', rows.slice(0, 20));
}

function explainFromScan(view){
  if (!view) return 'Paste a link and I will tell you what the checks found.';
  const lines = view.reasons.map(function(r){ return r.localized || r.message; }).filter(Boolean);
  if (!lines.length) return 'None of the checks found a problem. That lowers the risk, but it does not prove the site is safe.';
  return lines.join(' ');
}

const CATEGORY_VERDICT = {
  'Bank / Payment': 'phishing',
  'Social media login': 'phishing',
  'Parcel / Delivery': 'scam',
  'Prize / Giveaway': 'scam',
  'Crypto': 'scam',
  'Tech support': 'scam',
  'Other': 'scam'
};

async function sendReport(url, verdict, note){
  return api('/report', {
    method: 'POST',
    headers: {'content-type': 'application/json', 'x-reporter-token': reporterToken()},
    body: JSON.stringify({url: url, verdict: verdict, note: note || ''})
  });
}

// ============================================================
// Voice + chat. Explanations come from the last real scan, not a second model.
// ============================================================
const Settings = { autoSpeak: false, rate: 1, pitch: 1 };
const synth = window.speechSynthesis || null;
let speakToken = 0;
function canSpeak(){ return !!(synth && Settings.autoSpeak); }
function pickVoice(){ return null; }
function splitSentences(text){ return String(text).split(/(?<=[.!?])\s+/).filter(Boolean); }

async function askHachi({messages, context}){
  const last = (messages[messages.length - 1] && messages[messages.length - 1].content || '').toLowerCase();
  const view = context && context.view || lastScan;
  if (/^(hi|hello|hey|woof)|good (morning|evening)/.test(last)) {
    return {emotion: 'happy', text: "Woof! I'm Hachi. Paste a link and I will ask the Olfa service what it finds."};
  }
  if (/tip|advice|stay safe|protect/.test(last)) {
    return {emotion: 'happy', text: 'When a message makes you panic, stop. Open the company site by typing the address yourself, never through the link in the message.'};
  }
  if (/otp|password|bank|card/.test(last)) {
    return {emotion: 'suspicious', text: 'A real bank does not ask for your password or OTP in a message. If someone does, it is a scam. Call the number printed on your card.'};
  }
  if (/thank/.test(last)) return {emotion: 'happy', text: 'Anytime. Sniffing out scams is my favourite job.'};
  if (!view) return {emotion: 'neutral', text: 'I have not checked a link yet. Paste one on the home page.'};
  const emotion = view.verdict === 'dangerous' ? 'danger' : view.verdict === 'suspicious' ? 'suspicious' : 'safe';
  const pct = Math.round(view.score * 100);
  return {emotion: emotion, text: explainFromScan(view) + ' Risk from the service: ' + pct + ' out of 100.'};
}

function speak(text, hooks){
  hooks = hooks || {};
  stopSpeaking();
  if (!canSpeak()) { hooks.onEnd && hooks.onEnd(); return Promise.resolve(); }
  const token = ++speakToken;
  const parts = splitSentences(text);
  return new Promise(function(resolve){
    let i = 0, started = false;
    const next = function(){
      if (token !== speakToken) return resolve();
      if (i >= parts.length) { hooks.onEnd && hooks.onEnd(); return resolve(); }
      const u = new SpeechSynthesisUtterance(parts[i++]);
      u.rate = Settings.rate; u.pitch = Settings.pitch;
      u.onstart = function(){ if (!started) { started = true; hooks.onStart && hooks.onStart(); } };
      u.onend = function(){ setTimeout(next, 200); };
      u.onerror = function(){ resolve(); };
      synth.speak(u);
    };
    next();
  });
}
function stopSpeaking(){ speakToken++; if (synth) synth.cancel(); Talk.end(); }
function toSpoken(text){ return String(text).slice(0, 280); }

const Chat = { msgs: [], logs: new Set(), thinking: false };
const bubbles = new Set();
let typingJob = null;
function renderLogs(){
  Chat.logs.forEach(function(log){
    log.replaceChildren();
    if (!Chat.msgs.length) log.appendChild(el('<div class="msg sys">Say hi to Hachi</div>'));
    Chat.msgs.forEach(function(m){
      const d = document.createElement('div');
      d.className = 'msg ' + m.role;
      d.textContent = m.role === 'hachi' ? m.text.slice(0, m.shown) : m.text;
      log.appendChild(d);
    });
    if (Chat.thinking) {
      const s = document.createElement('div');
      s.className = 'msg sys';
      s.textContent = 'Hachi is thinking…';
      log.appendChild(s);
    }
    log.scrollTop = log.scrollHeight;
  });
}
function setBubbles(text, typing){
  bubbles.forEach(function(b){
    b.textContent = text || '';
  });
}
function stopTyping(){ if (typingJob) { typingJob.finish(); typingJob = null; } }
async function hachiSay(text, opts){
  opts = opts || {};
  stopTyping(); stopSpeaking();
  setHachiState(EMOTION_STATE[opts.emotion] || 'idle_breathing');
  const msg = {role: 'hachi', text: text, shown: 0};
  Chat.msgs.push(msg);
  let finished = false;
  const finish = function(){
    if (finished) return;
    finished = true;
    msg.shown = text.length;
    setBubbles(text, false);
    renderLogs();
    Talk.end();
  };
  typingJob = {finish: finish};
  let i = 0;
  const timer = setInterval(function(){
    i += 3;
    msg.shown = Math.min(text.length, i);
    setBubbles(text.slice(0, msg.shown), msg.shown < text.length);
    renderLogs();
    if (msg.shown >= text.length) { clearInterval(timer); finish(); typingJob = null; }
  }, 30);
}

function highlightClass(result){
  if (!result) return null;
  const score = typeof result.score === 'number' ? result.score : 0;
  if (result.level === 'dangerous' || score >= 0.75) return 'qr-unsafe';
  if (result.level === 'suspicious' || score >= 0.4) return 'qr-suspicious';
  return null;
}

function drawGauge(score){
  const pct = Math.round(clamp(score, 0, 1) * 100);
  const color = score >= 0.75 ? 'var(--red)' : score >= 0.4 ? 'var(--amber)' : 'var(--green)';
  const r = 78;
  const circ = 2 * Math.PI * r;
  const box = $('#gaugeBox');
  box.replaceChildren();
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'gauge');
  svg.setAttribute('viewBox', '0 0 200 200');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Risk ' + pct + ' out of 100');
  function ring(cls, dash, gap, stroke){
    const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    c.setAttribute('cx', '100'); c.setAttribute('cy', '100'); c.setAttribute('r', String(r));
    c.setAttribute('fill', 'none'); c.setAttribute('stroke-width', '16');
    if (cls) c.setAttribute('class', cls);
    if (stroke) c.setAttribute('stroke', stroke);
    if (dash != null) {
      c.setAttribute('stroke-dasharray', String(circ));
      c.setAttribute('stroke-dashoffset', String(gap));
      c.setAttribute('stroke-linecap', 'round');
      c.setAttribute('transform', 'rotate(-90 100 100)');
    }
    svg.appendChild(c);
  }
  ring('track');
  ring('fill', circ, circ * (1 - clamp(score, 0, 1)), color);
  const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  label.setAttribute('x', '100'); label.setAttribute('y', '108');
  label.setAttribute('text-anchor', 'middle');
  label.setAttribute('font-size', '42');
  label.setAttribute('font-family', 'Fredoka, Nunito, sans-serif');
  label.setAttribute('fill', '#14304A');
  label.textContent = String(pct);
  svg.appendChild(label);
  box.appendChild(svg);
}

function pillarLine(view){
  const parts = [];
  Object.keys(PILLAR_LABEL).forEach(function(key){
    const pillar = view.pillars[key];
    if (!pillar) return;
    const state = pillar.status === 'ok' ? pillar.level : pillar.status;
    parts.push(PILLAR_LABEL[key] + ': ' + state);
  });
  if (view.elapsed != null) parts.push(view.elapsed + ' ms');
  parts.push(view.deep ? 'full check' : 'quick check');
  return parts.join(' · ');
}

function showVerdict(view){
  lastScan = view;
  rememberScan(view);
  const card = $('#result');
  card.hidden = false;
  card.classList.remove('safe', 'suspicious', 'dangerous', 'qr-unsafe', 'qr-suspicious');
  card.classList.add(view.verdict);
  const hl = highlightClass({score: view.score, level: view.verdict});
  if (hl) card.classList.add(hl);
  drawGauge(view.score);
  const badge = $('#verdictBadge');
  const meta = VERDICTS[view.verdict] || VERDICTS.suspicious;
  badge.textContent = meta.label;
  badge.className = 'badge ' + view.verdict;
  $('#resultHost').textContent = view.host;
  const landed = view.finalUrl && view.finalUrl !== view.href ? ' Lands on ' + view.finalUrl + '.' : '';
  $('#resultMeta').textContent = pillarLine(view) + landed;
  const list = $('#reasonList');
  list.replaceChildren();
  const lines = view.reasons.length ? view.reasons : [{message: 'None of the checks found a problem.'}];
  lines.forEach(function(r){
    const li = document.createElement('li');
    li.textContent = r.localized || r.message || '';
    list.appendChild(li);
  });
  view.notes.forEach(function(note){
    const li = document.createElement('li');
    li.textContent = note;
    list.appendChild(li);
  });
  const explanation = explainFromScan(view);
  $('#hachiExplain').textContent = explanation;
  setHachiState(meta.state);
  if (view.verdict === 'dangerous') {
    $('#ovHost').textContent = view.host;
    $('#ovText').textContent = explanation;
    $('#overlay').hidden = false;
  }
}

function fillList(node, items, emptyText){
  node.replaceChildren();
  if (!items.length) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = emptyText;
    node.appendChild(p);
    return;
  }
  items.forEach(function(text){
    const row = document.createElement('div');
    row.style.padding = '8px 0';
    row.style.borderBottom = '1px solid var(--line)';
    row.textContent = text;
    node.appendChild(row);
  });
}

async function loadDashboard(){
  const scans = store.get('scans', []);
  let health = null, model = null, err = '';
  try {
    health = await api('/health');
    model = await api('/model');
  } catch (e) { err = e.message; }
  const cards = [
    ['Scans here', String(scans.length)],
    ['Community reports', health ? String(health.intel.reports) : '—'],
    ['Domains reported', health ? String(health.intel.domains) : '—'],
    ['Host model', model ? (model.available ? 'Loaded' : 'Off') : '—']
  ];
  const box = $('#statCards');
  box.replaceChildren();
  cards.forEach(function(pair){
    const card = document.createElement('div');
    card.className = 'card stat';
    const b = document.createElement('b');
    b.textContent = pair[1];
    const s = document.createElement('span');
    s.textContent = pair[0];
    card.append(b, s);
    box.appendChild(card);
  });
  const body = $('#recentRows');
  body.replaceChildren();
  scans.forEach(function(row){
    const tr = document.createElement('tr');
    [row.url, (VERDICTS[row.level] || {}).label || row.level, Math.round(row.score * 100) + '/100', timeAgo(row.at)].forEach(function(text, i){
      const td = document.createElement('td');
      if (i === 0) td.className = 'url';
      td.textContent = text;
      td.title = text;
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
  if (!scans.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.textContent = 'No scans in this browser yet.';
    tr.appendChild(td);
    body.appendChild(tr);
  }
  const metrics = $('#metricBars');
  metrics.replaceChildren();
  const note = $('#metricNote');
  if (!model) {
    note.textContent = err || 'Could not read the model card.';
  } else if (!model.available) {
    note.textContent = 'The host model did not load. ' + (model.error || '');
  } else {
    const auc = typeof model.auc === 'number' ? model.auc : null;
    const row = document.createElement('div');
    row.className = 'row';
    const name = document.createElement('span');
    name.textContent = model.version || 'olfa-host';
    const bar = document.createElement('div');
    bar.className = 'bar';
    const fill = document.createElement('i');
    fill.style.width = auc == null ? '0%' : Math.round(auc * 100) + '%';
    bar.appendChild(fill);
    const num = document.createElement('span');
    num.textContent = auc == null ? '—' : auc.toFixed(2);
    row.append(name, bar, num);
    metrics.appendChild(row);
    note.textContent = 'Held-out AUC from the trained model card. ' + model.role + ' Polarity: ' + model.polarity + '.';
  }
  const matrix = $('#confMatrix');
  matrix.replaceChildren();
  const mp = document.createElement('p');
  mp.className = 'muted';
  mp.textContent = 'This build does not ship a confusion matrix. The AUC above is the published held-out number, and only when the model files are loaded.';
  matrix.appendChild(mp);
  const feats = $('#featBars');
  feats.replaceChildren();
  const names = (model && model.features) || [];
  if (!names.length) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = model && model.available ? 'The model card has no feature list.' : 'Feature names appear when the host model loads.';
    feats.appendChild(p);
  } else {
    names.slice(0, 12).forEach(function(feature){
      const row = document.createElement('div');
      row.className = 'row';
      const name = document.createElement('span');
      name.textContent = feature;
      const bar = document.createElement('div');
      bar.className = 'bar';
      const fill = document.createElement('i');
      fill.style.width = '100%';
      fill.style.opacity = '0.35';
      bar.appendChild(fill);
      row.append(name, bar, document.createElement('span'));
      feats.appendChild(row);
    });
  }
}

async function loadCommunity(){
  let recent = [], feed = [], err = '';
  try {
    recent = (await api('/intel/recent?limit=30')).reports || [];
    feed = (await api('/intel/feed')).domains || [];
  } catch (e) { err = e.message; }
  const feedBox = $('#feed');
  if (err) fillList(feedBox, [], err);
  else fillList(feedBox, recent.map(function(r){
    const when = timeAgo(r.created * 1000);
    return r.domain + ' · ' + r.verdict + ' · ' + when + (r.note ? ' — ' + r.note : '');
  }), 'No reports yet. Be the first to send one.');
  const board = $('#leaderboard');
  board.replaceChildren();
  const domains = {};
  recent.forEach(function(r){ domains[r.domain] = (domains[r.domain] || 0) + 1; });
  const ranked = Object.keys(domains).sort(function(a, b){ return domains[b] - domains[a]; }).slice(0, 8);
  if (!ranked.length) {
    const li = document.createElement('li');
    li.textContent = 'Reports show up here after someone sends one. Names of reporters stay private.';
    board.appendChild(li);
  } else {
    ranked.forEach(function(domain){
      const li = document.createElement('li');
      li.textContent = domain + ' · ' + domains[domain] + ' report' + (domains[domain] === 1 ? '' : 's');
      board.appendChild(li);
    });
  }
  const trend = $('#trending');
  trend.replaceChildren();
  const counts = {};
  recent.forEach(function(r){ counts[r.verdict] = (counts[r.verdict] || 0) + 1; });
  const kinds = Object.keys(counts);
  if (!kinds.length && !feed.length) {
    const li = document.createElement('li');
    li.textContent = 'Nothing trending yet.';
    trend.appendChild(li);
  } else {
    kinds.forEach(function(kind){
      const li = document.createElement('li');
      li.textContent = kind + ' · ' + counts[kind];
      trend.appendChild(li);
    });
    feed.slice(0, 5).forEach(function(row){
      const li = document.createElement('li');
      li.textContent = 'Confirmed: ' + row.domain + ' (' + (row.verdict || 'malicious') + ', ' + row.reports + ' reports)';
      trend.appendChild(li);
    });
  }
}

function showPage(name){
  const known = ['home', 'dashboard', 'community', 'learn', 'extension'];
  if (known.indexOf(name) < 0) name = 'home';
  $$('.page').forEach(function(page){ page.hidden = page.dataset.page !== name; });
  $$('a.tab').forEach(function(tab){
    if (tab.dataset.tab === name) tab.setAttribute('aria-current', 'page');
    else tab.removeAttribute('aria-current');
  });
  document.body.dataset.tab = name;
  const heading = document.querySelector('.page:not([hidden]) h1');
  if (heading) heading.focus();
  if (name === 'dashboard') loadDashboard();
  if (name === 'community') loadCommunity();
}

function renderPopup(view){
  const mount = $('#popupMount');
  mount.replaceChildren();
  const card = document.createElement('div');
  card.className = 'card';
  card.style.width = '350px';
  card.style.minHeight = '180px';
  const title = document.createElement('h3');
  title.textContent = view ? view.host : 'Extension preview';
  const badge = document.createElement('p');
  badge.textContent = view ? ((VERDICTS[view.verdict] || {}).label + ' · ' + Math.round(view.score * 100) + '/100') : 'Pick a sample. The popup asks the same /scan endpoint.';
  card.append(title, badge);
  if (view) {
    const why = document.createElement('p');
    why.className = 'muted';
    why.textContent = explainFromScan(view);
    card.appendChild(why);
  }
  mount.appendChild(card);
}

// ============================================================
// Pages
// ============================================================
mountHachi($('#heroHachi'), {size: 'lg', wall: true, tag: true});
playIntro();
mountHachi($('#dockHachi'), {size: 'xs', tag: false});
mountHachi($('#panelHachi'), {size: 'xs', tag: false});
mountHachi($('#ovHachi'), {size: 'sm', tag: false});

const chat = document.createElement('div');
chat.className = 'chat';
const chatLog = document.createElement('div');
chatLog.className = 'log';
const chatForm = document.createElement('form');
chatForm.className = 'chat-form';
const chatInput = document.createElement('input');
chatInput.type = 'text';
chatInput.placeholder = 'Ask about the last scan';
chatInput.setAttribute('aria-label', 'Message to Hachi');
const chatSend = document.createElement('button');
chatSend.className = 'btn small';
chatSend.type = 'submit';
chatSend.textContent = 'Send';
chatForm.append(chatInput, chatSend);
chat.append(chatLog, chatForm);
$('#panelChatMount').appendChild(chat);
Chat.logs.add(chatLog);
renderLogs();

chatForm.addEventListener('submit', async function(e){
  e.preventDefault();
  const text = chatInput.value.trim();
  if (!text) return;
  chatInput.value = '';
  Chat.msgs.push({role: 'user', text: text, shown: text.length});
  renderLogs();
  Chat.thinking = true;
  renderLogs();
  const reply = await askHachi({messages: Chat.msgs.map(function(m){ return {role: m.role, content: m.text}; }), context: {view: lastScan}});
  Chat.thinking = false;
  hachiSay(reply.text, {emotion: reply.emotion});
});

function openChat(){
  $('#chatPanel').hidden = false;
  $('#chatToggle').setAttribute('aria-expanded', 'true');
  chatInput.focus();
}
$('#chatToggle').addEventListener('click', function(){
  const open = $('#chatPanel').hidden;
  $('#chatPanel').hidden = !open;
  $('#chatToggle').setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) chatInput.focus();
});
$('#chatClose').addEventListener('click', function(){
  $('#chatPanel').hidden = true;
  $('#chatToggle').setAttribute('aria-expanded', 'false');
});

$('#scanForm').addEventListener('submit', async function(e){
  e.preventDefault();
  const raw = $('#urlInput').value.trim();
  const button = $('#scanBtn');
  button.disabled = true;
  button.textContent = 'Scanning…';
  setHachiState('scanning_sniff');
  try {
    const view = await scanUrl(raw);
    showVerdict(view);
  } catch (err) {
    setHachiState('idle_breathing');
    toast(err.message || 'The scan failed.');
  } finally {
    button.disabled = false;
    button.textContent = 'Scan';
  }
});

$$('.chip[data-sample]').forEach(function(button){
  button.addEventListener('click', function(){
    $('#urlInput').value = button.dataset.sample;
    $('#scanForm').requestSubmit();
  });
});

$('#reportFromResult').addEventListener('click', function(){
  if (!lastScan) return;
  $('#rUrl').value = lastScan.href;
  location.hash = '#community';
  $('#rNote').focus();
});
$('#askMore').addEventListener('click', async function(){
  openChat();
  if (!lastScan) return;
  const reply = await askHachi({messages: [{content: 'why'}], context: {view: lastScan}});
  hachiSay(reply.text, {emotion: reply.emotion});
});

$('#reportForm').addEventListener('submit', async function(e){
  e.preventDefault();
  const url = $('#rUrl').value.trim();
  const category = $('#rCat').value;
  const note = [$('#rNote').value.trim(), category].filter(Boolean).join(' · ');
  const verdict = CATEGORY_VERDICT[category] || 'phishing';
  try {
    const saved = await sendReport(url, verdict, note);
    toast('Report saved for ' + saved.domain + ' (' + saved.status.replaceAll('_', ' ') + ').');
    $('#rNote').value = '';
    loadCommunity();
  } catch (err) {
    toast(err.message || 'Could not send the report.');
  }
});

$('#ovBack').addEventListener('click', function(){ $('#overlay').hidden = true; });
$('#ovProceed').addEventListener('click', function(){
  toast('You chose to continue. The warning stays on the record.');
  $('#overlay').hidden = true;
});

$$('[data-demo]').forEach(function(button){
  button.addEventListener('click', async function(){
    const sample = {safe: 'https://www.wikipedia.org', suspicious: 'http://secure-account-update.info/verify', dangerous: 'http://paypa1-login-verify.xyz/signin'}[button.dataset.demo];
    button.disabled = true;
    try {
      const view = await scanUrl(sample, false);
      renderPopup(view);
      if (view.verdict === 'dangerous') {
        $('#ovHost').textContent = view.host;
        $('#ovText').textContent = explainFromScan(view);
        $('#overlay').hidden = false;
      }
    } catch (err) {
      toast(err.message || 'The preview scan failed.');
    } finally {
      button.disabled = false;
    }
  });
});
$('#forceOverlay').addEventListener('click', function(){
  $('#ovHost').textContent = lastScan ? lastScan.host : 'example-phish.invalid';
  $('#ovText').textContent = lastScan ? explainFromScan(lastScan) : 'This is the warning screen. A dangerous verdict from /scan opens it on its own.';
  $('#overlay').hidden = false;
});
$('#installBtn').addEventListener('click', function(e){
  e.preventDefault();
  toast('Load features/qr-link-detector/extension unpacked. It calls this same service at /scan.');
});

const tips = [
  ['Check the real domain', 'The site name is the word just before the first slash, not the words at the front of the link.'],
  ['Do not log in from a message', 'Type the official address yourself when someone asks you to verify an account.'],
  ['Report it', 'A community report is stored by this service and counts on the next scan of that domain.']
];
const tipBox = $('#tips');
tips.forEach(function(tip){
  const card = document.createElement('div');
  card.className = 'card';
  const h = document.createElement('h3');
  h.textContent = tip[0];
  const p = document.createElement('p');
  p.className = 'muted';
  p.textContent = tip[1];
  card.append(h, p);
  tipBox.appendChild(card);
});

document.addEventListener('keydown', function(e){
  if (e.key === 'H' && e.ctrlKey && e.shiftKey) $('#devbar').hidden = false;
});
window.addEventListener('hashchange', function(){ showPage(location.hash.slice(1)); });
showPage((location.hash || '#home').slice(1));
renderPopup(null);
