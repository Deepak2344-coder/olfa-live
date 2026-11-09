/* Drives the page mascots (<hachi-dog id="heroDog"> and #chatDog) from scan/chat events. */
(function(){
  const M = {
    idle:       {dog:'idle',     rest:'idle',  t:'Paste a link, I\'ll sniff it out.', s:'I check the link, the page, the certificate and community reports.'},
    scanning:   {dog:'scanning', rest:'scanning', t:'Sniffing around…', s:'Following the link and checking the page.'},
    safe:       {dog:'safe',     rest:'idle',  t:'Smells safe to me!', s:'No warning signs found.'},
    suspicious: {dog:'error',    rest:'error', t:'Hmm, something smells off.', s:'Be careful with logins and downloads here.'},
    dangerous:  {dog:'phishing', rest:'error', t:'Woof! Do not open this!', s:'This looks like a phishing or malware trap.'},
    offline:    {dog:'offline',  rest:'offline', t:'I can\'t reach my nose…', s:'The Olfa service is asleep. Start it and try again.'}
  };
  const hero = document.getElementById('heroDog'), card = document.getElementById('heroCard');
  let rest = 'idle';
  if (hero) hero.addEventListener('ended', () => setTimeout(() => hero.setDog(rest), 0));
  window.olfaMood = function(key, subtitle){
    const m = M[key] || M.idle; if (!hero) return;
    rest = m.rest; card.dataset.mood = key;
    document.getElementById('heroTitle').textContent = m.t;
    document.getElementById('heroSub').textContent = subtitle || m.s;
    hero.setDog(m.dog);
  };
  const chat = document.getElementById('chatDog');
  window.olfaChatMood = function(thinking){ if (chat) chat.setDog(thinking ? 'scanning' : 'safe'); };
  if (chat) chat.addEventListener('ended', () => setTimeout(() => chat.setDog('idle'), 0));
})();
