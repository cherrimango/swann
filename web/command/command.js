// RAQEEB Command — police dashboard. Every value from the feed is attacker-controlled text,
// so the DOM is built with textContent only (no innerHTML with data).
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(path, body, method) {
  const opt = body !== undefined ? { method: method || 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : { method: method || 'GET' };
  const r = await fetch(path, opt);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
}

const ago = ts => {
  const s = Math.max(1, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
};
const verdictWord = v => ({ phishing: 'Phishing', suspicious: 'Suspicious', safe: 'Safe' }[v] || v);

function toast(title, text) {
  const t = h('div', { class: 'toast' }, h('b', {}, title), text || '');
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 6000);
}

/* ---------------- navigation ---------------- */
const loaders = {};
$$('.rail button').forEach(b => b.addEventListener('click', () => show(b.dataset.view)));
function show(view) {
  $$('.rail button').forEach(b => b.classList.toggle('on', b.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('on', v.id === `v-${view}`));
  loaders[view]?.();
}

/* ---------------- counters ---------------- */
async function loadStats() {
  const s = await api('/api/stats');
  $('#c-feed').textContent = s.feed_total.toLocaleString();
  $('#c-camp').textContent = s.campaigns;
  $('#c-block').textContent = s.blocked;
  $('#c-rep').textContent = s.reports;
}

/* ---------------- feed ---------------- */
let FEED = [], brandFilter = null, selectedUrl = null;
async function loadFeed() {
  FEED = await api('/api/feed?limit=400');
  renderChips();
  renderFeed();
}
function renderChips() {
  const counts = {};
  FEED.forEach(f => { if (f.brand) counts[f.brand] = (counts[f.brand] || 0) + 1; });
  const box = $('#brand-chips');
  box.replaceChildren(
    h('button', { class: brandFilter ? '' : 'on', onclick: () => { brandFilter = null; renderChips(); renderFeed(); } }, 'All brands'),
    ...Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([b, n]) =>
      h('button', { class: brandFilter === b ? 'on' : '', onclick: () => { brandFilter = b; renderChips(); renderFeed(); } }, `${b} ${n}`)));
}
function feedItem(f, fresh) {
  const li = h('li', { class: (fresh ? 'fresh ' : '') + (f.url === selectedUrl ? 'sel' : ''), tabindex: 0, onclick: () => select(f.url, li) },
    h('div', { class: `score ${f.verdict}` }, Math.round(f.risk), h('small', {}, verdictWord(f.verdict))),
    h('div', {}, h('div', { class: 'host' }, f.host || f.url),
      h('div', { class: 'meta' }, [f.brand || 'No brand match', f.source, f.ts > 1e9 ? ago(f.ts) : ''].filter(Boolean).join('  ·  '))));
  li.addEventListener('keydown', e => { if (e.key === 'Enter') select(f.url, li); });
  return li;
}
function renderFeed() {
  const q = $('#feed-search').value.trim().toLowerCase();
  const items = FEED.filter(f => (!brandFilter || f.brand === brandFilter) &&
    (!q || (f.url + ' ' + f.brand).toLowerCase().includes(q)));
  $('#feed').replaceChildren(...items.map(f => feedItem(f)));
}
$('#feed-search').addEventListener('input', renderFeed);

async function select(url, li) {
  selectedUrl = url;
  $$('#feed li').forEach(x => x.classList.remove('sel'));
  li?.classList.add('sel');
  const box = $('#detail');
  box.className = 'detail';
  box.replaceChildren(h('p', { class: 'empty-text' }, 'Checking…'));
  const r = await api('/api/scan', { url });
  renderDetail(r, box);
}

/* ---------------- detail (shared by feed and scan) ---------------- */
function twinRow(label, segs, cls) {
  return h('div', { class: `twin-row ${cls}` }, h('span', { class: 'twin-label' }, label),
    h('span', { class: 'twin-host' }, segs.map(s => s.type === 'same' ? s.text : h('span', { class: s.type }, s.text))));
}
function renderDetail(r, box) {
  const b = r.impersonated_brand;
  const kids = [
    h('div', { class: 'verdict-line' }, h('span', { class: `verdict-word ${r.verdict}` }, verdictWord(r.verdict)),
      h('span', { class: 'verdict-score' }, `Risk ${r.risk_score} / 100`),
      b ? h('span', { class: 'verdict-score' }, `Impersonates ${b.name}`) : null),
    h('p', { class: 'full-url' }, r.url),
  ];
  if (b?.twin) {
    const t = b.twin;
    const note = t.unicode_tricks.length
      ? `Look-alike characters: ${t.unicode_tricks.map(u => `“${u.char}” is ${u.name} (${u.codepoint})`).join('; ')}. Shown to people as ${t.scam_host}, registered as ${t.scam_host_ascii}.`
      : `${Math.round(t.similarity * 100)}% similar to the official domain. Highlighted characters are the differences.`;
    kids.push(h('div', { class: 'twin', 'aria-label': 'Scam domain compared with the official domain' },
      twinRow('This link', t.scam_segments, 'scam'), twinRow('Official', t.official_segments, 'real'),
      h('p', { class: 'twin-note' }, note)));
  }
  kids.push(h('ul', { class: 'reasons' }, r.reasons.map(x => h('li', {}, h('span', {}, x.en), h('span', { class: 'ar', lang: 'ar' }, x.ar)))));
  if (b?.likely_scams?.length) kids.push(h('p', { class: 'scams' }, 'Scams seen with this brand: ' + b.likely_scams.map(s => s.en).join('; ')));
  const actions = h('div', { class: 'actions' });
  const blockBtn = h('button', { class: 'primary', onclick: async () => {
    blockBtn.disabled = true;
    await api('/api/antibody', { domain: r.host, brand: b?.name || '', reason: r.reasons[0]?.en || '' });
    blockBtn.replaceWith(h('span', { class: 'blocked-tag' }, `Blocked on every phone: ${r.host}`));
  } }, 'Block on every phone');
  if (r.blocked) actions.append(h('span', { class: 'blocked-tag' }, `Already blocked: ${r.host}`));
  else if (r.verdict !== 'safe') actions.append(blockBtn);
  const evBtn = h('button', { class: 'ghost', onclick: async () => {
    evBtn.textContent = 'Building evidence pack…'; evBtn.disabled = true;
    const e = await api('/api/evidence', { url: r.url });
    evBtn.replaceWith(h('a', { class: 'ghost', href: `/api/evidence/${e.case_id}/report`, target: '_blank' }, 'Open case report'),
      h('a', { class: 'ghost', href: `/api/evidence/${e.case_id}/zip` }, 'Download takedown pack'));
    if (e.result.live) renderFacts(e.result.live, box);
  } }, 'Create evidence pack');
  actions.append(evBtn);
  kids.push(actions);
  box.replaceChildren(...kids);
  if (r.live) renderFacts(r.live, box);
}
function renderFacts(live, box) {
  $('.facts', box)?.remove();
  const w = live.whois || {}, ho = live.hosting || {}, t = live.tls || {};
  const facts = [
    ['Final URL', live.final_url], ['Domain created', w.created ? `${w.created.slice(0, 10)} (${w.age_days} days)` : null],
    ['Registrar', w.registrar], ['Hosting IP', ho.ip], ['Network', [ho.network, ho.country].filter(Boolean).join(' · ')],
    ['TLS issuer', t.issuer], ['Page asks for', live.content?.asks_for?.join(', ')], ['Checked', live.checked_at?.uae],
    ['Note', live.fetch_error ? 'Site unreachable from here: verdict is from the link itself' : null],
  ].filter(([, v]) => v);
  if (facts.length) box.append(h('dl', { class: 'facts' }, facts.map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, v)))));
}

/* ---------------- scan view ---------------- */
$('#scan-form').addEventListener('submit', async e => {
  e.preventDefault();
  const box = $('#scan-result');
  box.replaceChildren(h('p', { class: 'empty-text' }, $('#scan-live').checked ? 'Running live checks…' : 'Checking…'));
  try { renderDetail(await api('/api/scan', { url: $('#scan-url').value, live: $('#scan-live').checked }), box); }
  catch (err) { box.replaceChildren(h('p', {}, `Couldn’t check that link: ${err.message}`)); }
});

/* ---------------- hunting ---------------- */
$$('[data-hunt]').forEach(b => b.addEventListener('click', async () => {
  $('#hunt-status').textContent = `Starting ${b.textContent.toLowerCase()}…`;
  await api('/api/hunt', { mode: b.dataset.hunt, limit: b.dataset.hunt === 'replay' ? 12 : 400 });
}));

/* ---------------- campaigns + graph ---------------- */
let CAMP = null, selectedKit = null;
loaders.campaigns = async () => {
  CAMP = CAMP || await api('/api/campaigns');
  $('#camp-list').replaceChildren(...CAMP.campaigns.map(c => {
    const li = h('li', { tabindex: 0, onclick: () => { selectedKit = 'kit:' + c.id; $$('#camp-list li').forEach(x => x.classList.remove('sel')); li.classList.add('sel'); } },
      h('div', { class: 'kit-sig' }, c.kit_signature),
      h('div', { class: 'camp-meta' }, `${c.domains.length} domains · ${c.url_count} URLs · ${c.brands.join(', ')}`),
      h('div', { class: 'camp-meta' }, c.domains.slice(0, 4).join(', ') + (c.domains.length > 4 ? '…' : '')));
    return li;
  }));
  startGraph(CAMP.graph);
};

let sim = null;
function startGraph(g) {
  const cv = $('#graph'), ctx = cv.getContext('2d');
  const fit = () => { const r = cv.getBoundingClientRect(), d = devicePixelRatio || 1; cv.width = r.width * d; cv.height = r.height * d; ctx.setTransform(d, 0, 0, d, 0, 0); };
  fit(); addEventListener('resize', fit);
  const W = () => cv.getBoundingClientRect().width, H = () => cv.getBoundingClientRect().height;
  const nodes = g.nodes.map((n, i) => ({ ...n, x: W() / 2 + Math.cos(i) * 200 * Math.random(), y: H() / 2 + Math.sin(i) * 200 * Math.random(), vx: 0, vy: 0 }));
  const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
  const links = g.edges.map(e => ({ s: byId[e.source], t: byId[e.target] })).filter(l => l.s && l.t);
  let hover = null, ticks = 0;
  cv.onmousemove = e => {
    const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    hover = nodes.find(n => (n.x - x) ** 2 + (n.y - y) ** 2 < 120) || null;
  };
  cv.onclick = () => { if (hover?.kind === 'kit') selectedKit = hover.id; };
  const radius = n => n.kind === 'brand' ? 14 : n.kind === 'kit' ? 9 : 5;
  if (sim) cancelAnimationFrame(sim);
  const frame = () => {
    if (ticks++ < 400) {
      for (const a of nodes) {
        for (const b of nodes) {
          if (a === b) continue;
          const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01, f = 1600 / d2;
          a.vx += dx * f / Math.sqrt(d2); a.vy += dy * f / Math.sqrt(d2);
        }
        a.vx += (W() / 2 - a.x) * 0.004; a.vy += (H() / 2 - a.y) * 0.004;
      }
      for (const l of links) {
        const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y, d = Math.hypot(dx, dy) || 1, k = (d - 70) * 0.02;
        l.s.vx += dx / d * k; l.s.vy += dy / d * k; l.t.vx -= dx / d * k; l.t.vy -= dy / d * k;
      }
      for (const n of nodes) { n.vx *= 0.82; n.vy *= 0.82; n.x += n.vx; n.y += n.vy; n.x = Math.max(20, Math.min(W() - 20, n.x)); n.y = Math.max(20, Math.min(H() - 50, n.y)); }
    }
    ctx.clearRect(0, 0, W(), H());
    const focus = hover?.id || selectedKit;
    const linked = new Set();
    if (focus) links.forEach(l => { if (l.s.id === focus || l.t.id === focus) { linked.add(l.s.id); linked.add(l.t.id); } });
    for (const l of links) {
      const on = focus && (l.s.id === focus || l.t.id === focus);
      ctx.strokeStyle = on ? 'rgba(232,163,61,.9)' : 'rgba(167,180,198,.22)'; ctx.lineWidth = on ? 1.6 : 1;
      ctx.beginPath(); ctx.moveTo(l.s.x, l.s.y); ctx.lineTo(l.t.x, l.t.y); ctx.stroke();
    }
    for (const n of nodes) {
      const dim = focus && !linked.has(n.id) && n.id !== focus;
      ctx.globalAlpha = dim ? 0.3 : 1;
      ctx.fillStyle = n.kind === 'brand' ? '#F1E9DC' : n.kind === 'kit' ? '#E8A33D' : '#7DB8E8';
      const r = radius(n);
      ctx.beginPath();
      if (n.kind === 'kit') { ctx.moveTo(n.x, n.y - r); ctx.lineTo(n.x + r, n.y); ctx.lineTo(n.x, n.y + r); ctx.lineTo(n.x - r, n.y); ctx.closePath(); }
      else ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fill();
      if (n.kind === 'brand' || n.id === focus || (focus && linked.has(n.id) && n.kind !== 'domain') || n === hover) {
        ctx.fillStyle = '#F1E9DC'; ctx.font = n.kind === 'brand' ? '600 14px Cairo, sans-serif' : '13px "Readex Pro", sans-serif';
        ctx.fillText(n.label.length > 44 ? n.label.slice(0, 42) + '…' : n.label, n.x + r + 6, n.y + 4);
      }
      if (focus && linked.has(n.id) && n.kind === 'domain') { ctx.fillStyle = '#A7B4C6'; ctx.font = '12px "Readex Pro", sans-serif'; ctx.fillText(n.label, n.x + 8, n.y + 4); }
    }
    ctx.globalAlpha = 1;
    sim = requestAnimationFrame(frame);
  };
  frame();
}

/* ---------------- scamcast ---------------- */
loaders.scamcast = async () => {
  const s = await api('/api/scamcast');
  $('#seasons').replaceChildren(...s.active.map(x => h('article', { class: 'season' },
    h('h3', {}, x.name), h('p', { class: 'ar', lang: 'ar' }, x.name_ar),
    h('p', { class: 'meta' }, `Watching ${x.watchlist_size} likely fake domains`),
    h('ul', {}, x.sample.slice(0, 5).map(d => h('li', {}, d))),
    h('button', { class: 'primary', onclick: async () => { show('feed'); $('#hunt-status').textContent = `Hunting: ${x.name}…`; await api('/api/hunt', { mode: 'scamcast', season: x.id }); } }, 'Hunt this season now'))));
};

/* ---------------- blocklist ---------------- */
loaders.blocklist = async () => {
  const rows = await api('/api/blocklist');
  $('#block-rows').replaceChildren(...(rows.length ? rows.map(r => h('tr', {},
    h('td', {}, r.domain), h('td', {}, r.brand || '–'), h('td', {}, r.reason || '–'), h('td', {}, ago(r.ts)),
    h('td', {}, h('button', { class: 'ghost', onclick: async () => { await api(`/api/antibody/${encodeURIComponent(r.domain)}`, undefined, 'DELETE'); loaders.blocklist(); loadStats(); } }, 'Remove'))))
    : [h('tr', {}, h('td', { colspan: 5 }, 'Nothing blocked yet. Open a site in the live feed and choose “Block on every phone”.'))]));
};

/* ---------------- reports ---------------- */
loaders.reports = async () => {
  const [rows, s] = await Promise.all([api('/api/reports'), api('/api/stats')]);
  $('#emirates').replaceChildren(...s.reports_by_emirate.map(e => h('div', {}, h('b', {}, e.n), e.emirate)));
  $('#report-rows').replaceChildren(...(rows.length ? rows.map(r => h('li', {},
    h('div', { class: `score ${r.verdict === 'scam' ? 'phishing' : r.verdict === 'suspicious' ? 'suspicious' : 'safe'}` }, Math.round(r.risk), h('small', {}, r.verdict)),
    h('div', {}, h('div', { class: 'preview' }, r.content), h('div', { class: 'meta' }, [r.brand, r.emirate, ago(r.ts)].filter(Boolean).join('  ·  ')))))
    : [h('li', {}, h('span', {}, ''), h('span', {}, 'No reports yet. Residents report from the RAQEEB app.'))]));
};

/* ---------------- phones modal ---------------- */
$('#btn-phones').addEventListener('click', async () => {
  const { url } = await api('/api/join-url');
  $('#qr').src = `/api/qr?data=${encodeURIComponent(url)}`;
  $('#join-url').textContent = url;
  $('#phones').hidden = false;
});
$('#phones-close').addEventListener('click', () => { $('#phones').hidden = true; });

/* ---------------- live socket ---------------- */
function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = () => { $('#live').className = 'live on'; $('#live').textContent = 'Live'; };
  ws.onclose = () => { $('#live').className = 'live off'; $('#live').textContent = 'Reconnecting'; setTimeout(connect, 2000); };
  ws.onmessage = ev => {
    const { event, data } = JSON.parse(ev.data);
    if (event === 'feed') {
      const f = { url: data.url, host: data.url.replace(/^https?:\/\//, '').split('/')[0], brand: data.brand, risk: data.risk, verdict: data.verdict, source: data.source, ts: Date.now() / 1000 };
      FEED.unshift(f);
      if (!brandFilter || brandFilter === f.brand) $('#feed').prepend(feedItem(f, true));
      loadStats();
    } else if (event === 'hunt') {
      $('#hunt-status').textContent = data.status === 'started' ? `Hunting (${data.mode})…` : `Done: checked ${data.checked}, ${data.found} live, ${data.flagged} flagged.`;
    } else if (event === 'antibody') {
      toast('Blocked on every phone', `${data.domain}${data.brand ? ' · ' + data.brand : ''}`); loadStats();
      if ($('#v-blocklist').classList.contains('on')) loaders.blocklist();
    } else if (event === 'report') {
      toast(`New report from ${data.emirate}`, `${data.verdict} · ${data.preview}`); loadStats();
      if ($('#v-reports').classList.contains('on')) loaders.reports();
    }
  };
}

loadStats(); loadFeed(); connect();
