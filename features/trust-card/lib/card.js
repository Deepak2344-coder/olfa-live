/**
 * Olfa trust-card — rendering.
 *
 * renderCard(container, input) draws the card; the same function is used for
 * the live preview, the PNG export (html-to-image snapshots the DOM) and the
 * share view (data decoded from the URL hash).
 *
 * Share links carry the whole card in the hash, so no server is involved:
 *   index.html#d=<base64url(JSON)>
 */
(function (root) {
  'use strict';

  const grade = root.OlfaGrade || (typeof require === 'function' ? require('./grade.js') : null);

  const GRADE_CLASS = { A: 'a', B: 'b', C: 'c', D: 'd', F: 'f' };

  /** Encode/decode the card payload for the share link. Unicode-safe. */
  function encodeShare(data) {
    const json = JSON.stringify(data);
    const base64 = btoa(unescape(encodeURIComponent(json)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodeShare(fragment) {
    try {
      const normalised = fragment.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(escape(atob(normalised))));
    } catch (e) {
      return null;
    }
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderCard(container, input) {
    const result = grade.computeGrade(input);
    container.textContent = '';

    const card = el('article', 'olfa-card');
    card.setAttribute('data-grade', GRADE_CLASS[result.grade]);

    /* header */
    const head = el('header', 'card-head');
    const brand = el('div', 'card-brand');
    const logo = document.createElement('img');
    logo.src = root.__OLFA_HACHI__ || 'hachi.png';
    logo.alt = 'Hachi';
    brand.appendChild(logo);
    const titles = el('div');
    titles.appendChild(el('div', 'card-app', 'Olfa Digital Trust Card'));
    titles.appendChild(el('h2', 'card-domain', result.domain));
    brand.appendChild(titles);
    head.appendChild(brand);

    const seal = el('div', 'card-seal');
    seal.appendChild(el('span', 'card-letter', result.grade));
    seal.appendChild(el('span', 'card-seal-label', 'grade'));
    head.appendChild(seal);
    card.appendChild(head);

    card.appendChild(el('p', 'card-verdict', result.verdict));

    /* sections */
    const list = el('dl', 'card-sections');
    for (const section of result.sections) {
      const row = el('div', 'card-row');
      const term = el('dt');
      term.appendChild(el('span', 'card-dot', ''));
      term.lastChild.classList.add(GRADE_CLASS[section.grade]);
      term.appendChild(el('span', 'card-label', section.label));
      const desc = el('dd');
      desc.appendChild(el('span', 'card-grade ' + GRADE_CLASS[section.grade], section.grade));
      desc.appendChild(el('span', 'card-detail', section.detail));
      row.append(term, desc);
      list.appendChild(row);
    }
    card.appendChild(list);

    if (result.highlights.length) {
      const hi = el('div', 'card-highlights');
      hi.appendChild(el('strong', null, 'Biggest concerns'));
      const ul = el('ul');
      for (const line of result.highlights) ul.appendChild(el('li', null, line));
      hi.appendChild(ul);
      card.appendChild(hi);
    }

    const foot = el('footer', 'card-foot');
    foot.appendChild(el('span', null, 'Checked by Olfa · ' + new Date(result.generatedAt).toLocaleDateString()));
    foot.appendChild(el('span', null, 'olfa.app/trust-card'));
    card.appendChild(foot);

    container.appendChild(card);
    return result;
  }

  const api = { renderCard, encodeShare, decodeShare };
  root.OlfaCard = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
