// RAQEEB Command 2.0. Every value from threats, reports and feeds is attacker-controlled text,
// so the DOM is built with textContent only (never innerHTML with data).
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

let TOKEN = sessionStorage.getItem('raqeeb_cmd_token');
let ME = null, META = null;

async function api(path, body, method) {
  const headers = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
  const opt = { method: method || (body !== undefined ? 'POST' : 'GET'), headers };
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401 && !path.startsWith('/api/auth/login')) { signOut(); throw new Error('Your session ended. Sign in again.'); }
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* not JSON */ }
    throw new Error(msg);
  }
  return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
}
async function authedBlob(path) {
  const r = await fetch(path, { headers: { Authorization: `Bearer ${TOKEN}` } });
  if (!r.ok) throw new Error(`${r.status}`);
  return URL.createObjectURL(await r.blob());
}
async function download(path, name) {
  const a = h('a', { href: await authedBlob(path), download: name });
  document.body.append(a); a.click(); a.remove();
}

const can = perm => !!ME?.permissions.includes(perm);
const ago = ts => {
  if (!ts || ts < 1e9) return '';
  const s = Math.max(1, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
};
const when = ts => ts ? new Date(ts * 1000).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '–';
const verdictWord = v => ({ phishing: 'Phishing', suspicious: 'Suspicious', safe: 'Safe', scam: 'Scam' }[v] || v);
const statusLabel = s => META?.statuses[s] || s;
const catLabel = c => META?.categories[c] || c;
const pill = (s, extra = '') => h('span', { class: `pill ${s} ${extra}` }, statusLabel(s));

function toast(title, text) {
  const t = h('div', { class: 'toast' }, h('b', {}, title), text || '');
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 6000);
}
async function act(btn, fn, okTitle) {
  const label = btn.textContent;
  btn.disabled = true;
  try { const r = await fn(); if (okTitle) toast(okTitle); return r; }
  catch (e) { toast('That didn’t work', e.message); }
  finally { btn.disabled = false; btn.textContent = label; }
}

/* ---------------- sign in ---------------- */
$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('#login-error').textContent = '';
  try {
    const r = await api('/api/auth/login', { email: $('#l-email').value, password: $('#l-pass').value });
    if (r.user.role === 'citizen') { $('#login-error').textContent = 'This account is a citizen account. Use RAQEEB Protect at /app.'; return; }
    TOKEN = r.token; sessionStorage.setItem('raqeeb_cmd_token', TOKEN);
    start();
  } catch (err) { $('#login-error').textContent = err.message; }
});
let DEMO = { enabled: false, accounts: [] };
async function loadDemoLogins() {
  try { DEMO = await (await fetch('/api/public/demo')).json(); } catch { return; }
  const box = $('#demo-logins');
  if (!DEMO.enabled) return;
  box.hidden = false;
  DEMO.accounts.filter(a => a.app === 'command').forEach(a => box.append(h('button', { type: 'button', onclick: () => {
    $('#l-email').value = a.email; $('#l-pass').value = a.password; $('#login-form').requestSubmit();
  } }, h('b', {}, a.label), h('small', {}, a.email))));
  const want = decodeURIComponent((location.hash.match(/demo=([^&]+)/) || [])[1] || '');
  const acct = DEMO.accounts.find(a => a.email === want && a.app === 'command');
  if (acct && !TOKEN) { $('#l-email').value = acct.email; $('#l-pass').value = acct.password; }
}
function signOut() {
  if (TOKEN) fetch('/api/auth/logout', { method: 'POST', headers: { Authorization: `Bearer ${TOKEN}` } });
  TOKEN = null; ME = null; sessionStorage.removeItem('raqeeb_cmd_token');
  document.body.classList.add('signed-out');
  socket?.close();
}
$('#btn-logout').addEventListener('click', signOut);
$('#nav-toggle').addEventListener('click', () => {
  const c = document.body.classList.toggle('nav-collapsed');
  $('#nav-toggle').setAttribute('aria-expanded', String(!c));
});

async function start() {
  try { ME = await api('/api/auth/me'); } catch { signOut(); return; }
  if (ME.role === 'citizen') { signOut(); return; }
  META = META || await api('/api/public/meta');
  document.body.classList.remove('signed-out');
  $('#who-name').textContent = ME.display_name;
  $('#who-role').textContent = ME.role_name;
  $$('[data-perm]').forEach(el => { el.hidden = !can(el.dataset.perm); });
  $('#t-status').replaceChildren(h('option', { value: '' }, 'All statuses'),
    ...Object.entries(META.statuses).map(([k, v]) => h('option', { value: k }, v)));
  $('#demo-flag').hidden = !DEMO.enabled;
  $('#nav-demo').hidden = !DEMO.enabled;
  show(DEMO.enabled && location.hash.includes('demo') ? 'demo' : 'overview');
  loadCounters();
  connect();
}

/* ---------------- navigation ---------------- */
const loaders = {};
$$('.rail button').forEach(b => b.addEventListener('click', () => show(b.dataset.view)));
function show(view) {
  $$('.rail button').forEach(b => b.classList.toggle('on', b.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('on', v.id === `v-${view}`));
  loaders[view]?.().catch(e => toast('Couldn’t load this view', e.message));
}
const onView = v => $(`#v-${v}`).classList.contains('on');

/* ---------------- counters + overview ---------------- */
let OV = null;
async function loadCounters() {
  OV = await api('/api/command/overview');
  $('#c-review').textContent = OV.under_review + OV.corroborated;
  $('#c-await').textContent = OV.awaiting_block;
  $('#c-block').textContent = OV.blocked;
  $('#c-rep').textContent = OV.reports_today;
  const n = OV.under_review + OV.corroborated;
  $('#n-review').hidden = !n; $('#n-review').textContent = n;
}

// schematic layout of the seven emirates (west to east, north to south) as grid areas
const MAP_AREA = { 'Abu Dhabi': 'ad', 'Dubai': 'dxb', 'Sharjah': 'shj', 'Ajman': 'ajm', 'Umm Al Quwain': 'uaq', 'Ras Al Khaimah': 'rak', 'Fujairah': 'fuj' };
function renderMap(geo, box) {
  const max = Math.max(1, ...geo.map(g => g.reports + g.threats));
  const detail = g => {
    const cats = Object.entries(g.categories || {}).sort((x, y) => y[1] - x[1]).map(([c, n]) => `${catLabel(c)} (${n})`).join(', ');
    $('#map-detail').textContent = `${g.emirate}: ${g.reports} citizen reports, ${g.threats} threats, ${g.confirmed} officially approved` +
      (g.campaigns?.length ? `, campaigns ${g.campaigns.join(', ')}` : '') + (cats ? `. Categories: ${cats}.` : '.') +
      ' Reporting location is where citizens reported from, not where criminals are.';
  };
  box.replaceChildren(...geo.map(g => {
    const heat = g.reports + g.threats === 0 ? 0 : Math.ceil(3 * (g.reports + g.threats) / max);
    const t = h('button', { class: `tile heat-${heat}`, style: `grid-area:${MAP_AREA[g.emirate]}`, onclick: () => { $$('.tile', box).forEach(x => x.classList.remove('sel')); t.classList.add('sel'); detail(g); } },
      h('b', {}, g.emirate), h('span', { class: 'n' }, g.reports), ' reports · ', h('span', { class: 'n' }, g.threats), ' threats');
    return t;
  }));
}
function bars(box, items, labelFn, warm) {
  const max = Math.max(1, ...items.map(i => i.n));
  box.replaceChildren(...(items.length ? items.map(i => h('div', { class: `bar ${warm ? 'warm' : ''}` },
    h('span', {}, labelFn(i)), h('i', { style: `width:${Math.round(100 * i.n / max)}%` }), h('b', {}, i.n))) : [h('p', { class: 'note' }, 'Nothing yet.')]));
}
const clock = ts => new Date(ts * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
loaders.overview = async () => {
  const [ov, geo, br, act] = await Promise.all([api('/api/command/overview'), api('/api/intel/geography'), api('/api/intel/briefing?period=day'), api('/api/command/activity')]);
  OV = ov;
  const k = [['Threats discovered today', ov.new_today], ['Suspicious domains observed today', ov.suspicious_domains_today],
    ['Look-alike websites', ov.lookalikes], ['Known malicious indicators', ov.known_malicious, 'bad'], ['Active scam campaigns', ov.campaigns],
    ['Citizen reports awaiting review', ov.reports_awaiting, 'attn'], ['Analyst verified', ov.analyst_verified], ['Officially approved', ov.confirmed, 'ok'],
    ['Awaiting block decision', ov.awaiting_block, 'attn'], ['Blocked for everyone', ov.blocked]];
  $('#ov-kpis').replaceChildren(...k.map(([t, v, cls]) => h('div', { class: cls && v ? cls : '' }, h('dt', {}, t), h('dd', {}, v))));
  $('#ov-season').textContent = ov.active_seasons.length ? `Seasonal watch: ${ov.active_seasons.slice(0, 2).join(' · ')}` : '';
  renderMap(geo, $('#map'));
  $('#map-detail').textContent = 'Select an emirate for its breakdown.';
  $('#ov-brief').textContent = br.summary;
  $('#ov-actions').replaceChildren(...(br.recommended_actions.length ? br.recommended_actions.map(a => h('li', {}, a)) : [h('li', {}, 'No pending decisions.')]));
  bars($('#ov-status'), ov.by_status, i => statusLabel(i.status));
  bars($('#ov-brands'), ov.by_brand, i => i.brand, true);
  $('#ov-activity').replaceChildren(...(act.length ? act.map(i => h('li', {}, h('time', {}, clock(i.ts)),
    h('div', {}, h('b', {}, i.title), i.demo ? h('span', { class: 'pill demo', style: 'margin-left:8px' }, 'Demo') : null, h('span', { class: 'meta' }, i.detail))))
    : [h('li', {}, h('span', {}), h('span', { class: 'meta' }, 'No activity yet. Run a hunt, or wait for citizen reports.'))]));
  $('#ov-sub').textContent = `Signed in as ${ME.display_name}${ME.display_name !== ME.role_name ? ` (${ME.role_name})` : ''}. Live state of RAQEEB across the UAE.`;
};

/* ---------------- threats workspace ---------------- */
let THREATS = [], selectedThreat = null;
loaders.threats = async () => {
  const q = encodeURIComponent($('#t-search').value.trim()), st = $('#t-status').value;
  THREATS = await api(`/api/threats?q=${q}${st ? `&status=${st}` : ''}`);
  $('#t-count').textContent = `${THREATS.length} threat${THREATS.length === 1 ? '' : 's'}`;
  $('#t-list').replaceChildren(...(THREATS.length ? THREATS.map(threatItem) : [h('li', {}, h('span', {}), h('span', { class: 'meta' }, 'No threats match. Citizen reports and promoted hunt results appear here.'))]));
  if (selectedThreat) $$('#t-list li').find(li => li.dataset.id === selectedThreat)?.classList.add('sel');
};
let tTimer;
$('#t-search').addEventListener('input', () => { clearTimeout(tTimer); tTimer = setTimeout(loaders.threats, 250); });
$('#t-status').addEventListener('change', loaders.threats);
function threatItem(t) {
  const v = t.risk >= 70 ? 'phishing' : t.risk >= 40 ? 'suspicious' : 'safe';
  const li = h('li', { tabindex: 0, 'data-id': t.id, onclick: () => openThreat(t.id) },
    h('div', { class: `score ${v}` }, Math.round(t.risk || 0), h('small', {}, t.severity || '')),
    h('div', {}, h('div', { class: 'host' }, t.normalized),
      h('div', { class: 'meta' }, h('span', { class: 't-id' }, t.id), '  ', pill(t.status), t.block_status === 'global' ? h('span', { class: 'pill global' }, 'Blocked') : null,
        t.demo ? h('span', { class: 'pill demo' }, 'Demo') : null),
      h('div', { class: 'meta' }, [catLabel(t.category), t.brand, `${t.report_count} report${t.report_count === 1 ? '' : 's'}`, ago(t.last_seen)].filter(Boolean).join('  ·  '))));
  li.addEventListener('keydown', e => { if (e.key === 'Enter') openThreat(t.id); });
  return li;
}
const DECISIONS = [
  ['analyst_verified', 'Mark analyst verified'], ['confirmed_malicious', 'Officially approve'], ['rejected', 'Reject'],
  ['false_positive', 'False positive'], ['duplicate', 'Duplicate'], ['resolved', 'Resolved'], ['under_review', 'Back to review'],
];
async function openThreat(id) {
  selectedThreat = id;
  $$('#t-list li').forEach(li => li.classList.toggle('sel', li.dataset.id === id));
  const box = $('#t-detail');
  box.className = 'detail';
  box.replaceChildren(h('p', { class: 'empty-text' }, 'Loading…'));
  const t = await api(`/api/threats/${encodeURIComponent(id)}`);
  const kids = [
    h('div', { class: 'verdict-line' }, h('span', { class: 'verdict-word', style: 'font-size:28px' }, t.id), pill(t.status),
      t.block_status === 'global' ? h('span', { class: 'pill global' }, `Blocked (${t.block_scope})`) : t.block_status !== 'none' ? h('span', { class: 'pill' }, t.block_status) : null),
    t.demo ? h('p', { class: 'pill demo' }, 'Demonstration record (seeded)') : null,
    h('p', { class: 'full-url' }, t.original),
    h('dl', { class: 'facts' }, [
      ['Indicator', `${t.indicator_type}: ${t.normalized}`], ['Category', catLabel(t.category)], ['Impersonates', t.brand || '–'],
      ['AI risk', `${Math.round(t.risk || 0)} / 100 (${t.severity})`], ['Confidence', `${Math.round((t.ai_confidence || 0) * 100)}%`],
      ['Reports', t.report_count], ['Citizens corroborating', t.corroborations], ['First seen', when(t.first_seen)], ['Last seen', when(t.last_seen)],
      ['Emirates', Object.entries(t.emirates || {}).map(([e, n]) => `${e} (${n})`).join(', ') || '–'], ['Campaign', t.campaign_id || '–'],
      ['Source', t.source || '–'], ['Block expires', t.block_status === 'global' ? when(t.block_expires) : '–'],
    ].map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, v)))),
    h('div', { style: 'height:18px' }),
  ];
  if (can('verify_threat')) {
    kids.push(h('h3', { class: 'section-h' }, 'Review decision'),
      h('div', { class: 'decide' }, DECISIONS.filter(([s]) => s !== t.status && (s !== 'confirmed_malicious' || can('approve_threat'))).map(([s, label]) => {
        const b = h('button', { class: 'ghost', onclick: () => act(b, async () => {
          const note = s === 'false_positive' || s === 'rejected' ? prompt('Reason (recorded in the audit log):') || '' : '';
          await api(`/api/threats/${t.id}/status`, { status: s, note });
          openThreat(t.id); loaders.threats(); loadCounters();
        }, `${t.id}: ${label.toLowerCase()}`) }, label);
        return b;
      })));
  }
  if (can('approve_block')) {
    const days = h('select', { 'aria-label': 'Block expiry' }, [7, 14, 30, 90].map(d => h('option', { value: d, selected: d === 30 }, `${d} days`)));
    const scope = t.policy.scope;
    const box2 = h('div', { class: 'block-box' });
    if (t.block_status === 'global') {
      const b = h('button', { class: 'ghost', onclick: () => act(b, async () => { await api(`/api/threats/${t.id}/unblock`, { status: 'none', note: 'lifted by approver' }); openThreat(t.id); loadCounters(); }, 'Block lifted') }, 'Lift block');
      box2.append(h('p', {}, `Blocked for every RAQEEB user as a ${t.block_scope} rule until ${when(t.block_expires)}.`), b);
    } else if (t.policy.can_block_globally) {
      const b = h('button', { class: 'primary', onclick: () => act(b, async () => { await api(`/api/threats/${t.id}/block`, { expiry_days: +days.value }); openThreat(t.id); loadCounters(); }, 'Published to every phone') }, 'Approve global block');
      box2.append(h('p', {}, `Will block the ${scope[0]} “${scope[1]}” for everyone and publish a new signed version.`), days, b);
    } else {
      box2.append(h('p', {}, 'Global blocking is available once an authorised official has approved the threat (Officially approved).'));
    }
    kids.push(box2);
  }
  const tools = h('div', { class: 'actions' });
  if (['url', 'domain', 'qr'].includes(t.indicator_type)) {
    tools.append(h('button', { class: 'ghost', onclick: () => { show('domain'); $('#scan-url').value = t.original; setMode('deep'); $('#scan-form').requestSubmit(); } }, 'Investigate in Domain Intelligence'));
  }
  if (can('view_evidence') && ['url', 'domain', 'qr'].includes(t.indicator_type)) {
    const ev = h('button', { class: 'ghost', onclick: () => act(ev, async () => {
      ev.textContent = 'Collecting live evidence…';
      const r = await api(`/api/threats/${t.id}/evidence`, {});
      tools.append(h('button', { class: 'ghost', onclick: async () => window.open(await authedBlob(`/api/evidence/${r.case_id}/report`)) }, 'Open case report'),
        h('button', { class: 'ghost', onclick: () => download(`/api/evidence/${r.case_id}/zip`, `raqeeb-case-${r.case_id}.zip`) }, 'Download takedown pack'));
      renderFacts(r.live, box);
    }, 'Evidence collected') }, 'Collect live evidence');
    tools.append(ev);
  }
  if (can('view_evidence')) tools.append(h('button', { class: 'ghost', onclick: () => download(`/api/threats/${t.id}/export`, `${t.id}.json`) }, 'Export case file'));
  kids.push(tools);

  kids.push(h('h3', { class: 'section-h' }, `Linked citizen reports (${t.reports.length})`),
    h('ol', { class: 'linked' }, t.reports.length ? t.reports.map(r => {
      const li = h('li', {}, h('div', { class: 'meta' }, `${r.ref} · ${r.type} · ${r.emirate || 'emirate not given'} · ${when(r.created)} · `, pill(r.status)),
        h('div', {}, r.text || '(screenshot only)'),
        Object.entries(r.impact || {}).some(([, v]) => v) ? h('div', { class: 'meta' }, 'Impact: ' + Object.entries(r.impact).filter(([, v]) => v).map(([k]) => k.replace('_', ' ')).join(', ')) : null);
      if (r.attachment) authedBlob(`/api/uploads/${r.attachment}`).then(u => li.append(h('img', { src: u, alt: `Screenshot attached to ${r.ref}` }))).catch(() => {});
      else if (r.has_attachment) li.append(h('div', { class: 'meta' }, 'Screenshot attached (your role can’t view evidence).'));
      return li;
    }) : [h('li', {}, 'No citizen reports: added by an analyst or the threat hunter.')]));

  const obs = (t.evidence?.observations || []).slice(-1)[0];
  if (obs?.reasons?.length) kids.push(h('h3', { class: 'section-h' }, 'Why the AI flagged it'), h('ul', { class: 'reasons' }, obs.reasons.map(x => h('li', {}, h('span', {}, x)))));
  if (t.findings.length) kids.push(h('h3', { class: 'section-h' }, 'Agent findings'), h('ul', { class: 'linked' }, t.findings.map(f =>
    h('li', {}, h('b', {}, f.agent.replace(/_/g, ' ')), ` · ${Math.round(f.confidence * 100)}% · ${f.reasoning}`, f.next_action ? h('div', { class: 'meta' }, `Next: ${f.next_action}`) : null))));

  kids.push(h('h3', { class: 'section-h' }, 'Investigation notes'));
  if (can('edit_investigation')) {
    const inp = h('input', { placeholder: 'Add a note for the investigation team', 'aria-label': 'New note', maxlength: 2000 });
    kids.push(h('form', { class: 'note-form', onsubmit: async e => { e.preventDefault(); if (!inp.value.trim()) return; await api(`/api/threats/${t.id}/notes`, { note: inp.value }); openThreat(t.id); } },
      inp, h('button', { class: 'ghost', type: 'submit' }, 'Add note')));
  }
  kids.push(h('ul', { class: 'linked' }, t.notes.length ? t.notes.map(n => h('li', {}, h('div', { class: 'meta' }, `${n.author} · ${when(n.created)}`), n.note)) : [h('li', { class: 'meta' }, 'No notes yet.')]));
  kids.push(h('h3', { class: 'section-h' }, 'History'), h('ol', { class: 'timeline' }, [...t.history].reverse().map(x =>
    h('li', { class: ['status', 'global_block', 'rollback', 'unblock'].includes(x.event) ? 'key' : '' },
      h('b', {}, x.event.replace(/_/g, ' ')), x.status ? ` → ${statusLabel(x.status)}` : '', ` · ${x.by || ''} · ${when(x.ts)}`, x.note ? h('div', { class: 'meta' }, x.note) : null))));
  box.replaceChildren(...kids);
}
$('#t-add').addEventListener('click', () => { $('#add-threat').hidden = false; $('#add-value').focus(); });
$('#add-cancel').addEventListener('click', () => { $('#add-threat').hidden = true; });
$('#add-form').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const t = await api('/api/threats', { indicator: $('#add-value').value, indicator_type: $('#add-type').value, note: $('#add-note').value });
    $('#add-threat').hidden = true; $('#add-form').reset();
    await loaders.threats(); openThreat(t.id);
  } catch (err) { toast('Couldn’t add the threat', err.message); }
});

/* ---------------- citizen reports ---------------- */
let rFilter = '';
loaders.reports = async () => {
  const opts = [['', 'All'], ['under_review', 'Under review'], ['community_corroborated', 'Corroborated'], ['confirmed_malicious', 'Confirmed'], ['duplicate', 'Duplicates'], ['false_positive', 'False positives']];
  $('#r-filter').replaceChildren(...opts.map(([k, v]) => h('button', { class: rFilter === k ? 'on' : '', onclick: () => { rFilter = k; loaders.reports(); } }, v)));
  const rows = await api(`/api/reports/queue${rFilter ? `?status=${rFilter}` : ''}`);
  $('#r-list').replaceChildren(...(rows.length ? rows.map(r => {
    const ai = r.ai || {}, risk = ai.risk ?? 0;
    return h('li', {},
      h('div', { class: `score ${risk >= 70 ? 'phishing' : risk >= 40 ? 'suspicious' : 'safe'}` }, Math.round(risk), h('small', {}, ai.severity || '')),
      h('div', {},
        h('div', { class: 'meta' }, `${r.ref} · ${META.report_types[r.type] || r.type} · ${r.emirate || 'emirate not given'} · ${ago(r.created)} · `, pill(r.status),
          r.reporter ? ` · reputation ${r.reporter.reputation.toFixed(2)}` : ' · anonymous'),
        h('div', { class: 'preview' }, r.raw_text || '(screenshot only)'),
        h('p', { class: 'meta' }, ai.explanation_en || ''),
        h('div', { class: 'actions' }, (r.threat_ids || []).map(id => h('button', { class: 'ghost small', onclick: () => { show('threats'); openThreat(id); } }, `Open ${id}`)))));
  }) : [h('li', {}, h('span', {}), h('span', {}, 'No reports in this view.'))]));
};

/* ---------------- hunt feed (1.0, kept) ---------------- */
let FEED = [], brandFilter = null, selectedUrl = null;
loaders.feed = async () => { FEED = await api('/api/feed?limit=400'); renderChips(); renderFeed(); };
function renderChips() {
  const counts = {};
  FEED.forEach(f => { if (f.brand) counts[f.brand] = (counts[f.brand] || 0) + 1; });
  $('#brand-chips').replaceChildren(
    h('button', { class: brandFilter ? '' : 'on', onclick: () => { brandFilter = null; renderChips(); renderFeed(); } }, 'All brands'),
    ...Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([b, n]) =>
      h('button', { class: brandFilter === b ? 'on' : '', onclick: () => { brandFilter = b; renderChips(); renderFeed(); } }, `${b} ${n}`)));
}
function feedItem(f, fresh) {
  const li = h('li', { class: (fresh ? 'fresh ' : '') + (f.url === selectedUrl ? 'sel' : ''), tabindex: 0, onclick: () => select(f.url, li) },
    h('div', { class: `score ${f.verdict}` }, Math.round(f.risk), h('small', {}, verdictWord(f.verdict))),
    h('div', {}, h('div', { class: 'host' }, f.host || f.url),
      h('div', { class: 'meta' }, [f.brand || 'No brand match', f.source, ago(f.ts)].filter(Boolean).join('  ·  '))));
  li.addEventListener('keydown', e => { if (e.key === 'Enter') select(f.url, li); });
  return li;
}
function renderFeed() {
  const q = $('#feed-search').value.trim().toLowerCase();
  const items = FEED.filter(f => (!brandFilter || f.brand === brandFilter) && (!q || (f.url + ' ' + f.brand).toLowerCase().includes(q)));
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
  renderDetail(await api('/api/scan', { url }), box);
}
function twinRow(label, segs, cls) {
  return h('div', { class: `twin-row ${cls}` }, h('span', { class: 'twin-label' }, label),
    h('span', { class: 'twin-host' }, segs.map(s => s.type === 'same' ? s.text : h('span', { class: s.type }, s.text))));
}
function renderDetail(r, box) {
  const b = r.impersonated_brand;
  const kids = [
    h('div', { class: 'verdict-line' }, h('span', { class: `verdict-word ${r.verdict}` }, verdictWord(r.verdict)),
      h('span', { class: 'verdict-score' }, `Risk ${r.risk_score} / 100`), b ? h('span', { class: 'verdict-score' }, `Impersonates ${b.name}`) : null),
    h('p', { class: 'full-url' }, r.url),
  ];
  if (b?.twin) {
    const t = b.twin;
    const note = t.unicode_tricks.length
      ? `Look-alike characters: ${t.unicode_tricks.map(u => `“${u.char}” is ${u.name} (${u.codepoint})`).join('; ')}. Shown to people as ${t.scam_host}, registered as ${t.scam_host_ascii}.`
      : `${Math.round(t.similarity * 100)}% similar to the official domain. Highlighted characters are the differences.`;
    kids.push(h('div', { class: 'twin', 'aria-label': 'Scam domain compared with the official domain' },
      twinRow('This link', t.scam_segments, 'scam'), twinRow('Official', t.official_segments, 'real'), h('p', { class: 'twin-note' }, note)));
  }
  kids.push(h('ul', { class: 'reasons' }, r.reasons.map(x => h('li', {}, h('span', {}, x.en), h('span', { class: 'ar', lang: 'ar' }, x.ar)))));
  if (b?.likely_scams?.length) kids.push(h('p', { class: 'scams' }, 'Scams seen with this brand: ' + b.likely_scams.map(s => s.en).join('; ')));
  const actions = h('div', { class: 'actions' });
  if (r.blocked) actions.append(h('span', { class: 'blocked-tag' }, `Already blocked: ${r.host}`));
  else if (r.verdict !== 'safe' && can('verify_threat')) {
    const p = h('button', { class: 'primary', onclick: () => act(p, async () => {
      const t = await api('/api/intel/early-watch/promote', { url: r.url, note: r.reasons[0]?.en || '' });
      p.replaceWith(h('button', { class: 'ghost', onclick: () => { show('threats'); openThreat(t.id); } }, `Open ${t.id}`));
    }, 'Threat record opened for review') }, 'Open threat record');
    actions.append(p);
  }
  if (can('view_evidence')) {
    const evBtn = h('button', { class: 'ghost', onclick: () => act(evBtn, async () => {
      evBtn.textContent = 'Building evidence pack…';
      const e = await api('/api/evidence', { url: r.url });
      evBtn.replaceWith(h('button', { class: 'ghost', onclick: async () => window.open(await authedBlob(`/api/evidence/${e.case_id}/report`)) }, 'Open case report'),
        h('button', { class: 'ghost', onclick: () => download(`/api/evidence/${e.case_id}/zip`, `raqeeb-case-${e.case_id}.zip`) }, 'Download takedown pack'));
      if (e.result.live) renderFacts(e.result.live, box);
    }) }, 'Create evidence pack');
    actions.append(evBtn);
  }
  kids.push(actions);
  box.replaceChildren(...kids);
  if (r.live) renderFacts(r.live, box);
}
function renderFacts(live, box) {
  $('.facts.live', box)?.remove();
  const w = live.whois || {}, ho = live.hosting || {}, t = live.tls || {};
  const facts = [
    ['Final URL', live.final_url], ['Domain created', w.created ? `${w.created.slice(0, 10)} (${w.age_days} days)` : null],
    ['Registrar', w.registrar], ['Hosting IP', ho.ip], ['Network', [ho.network, ho.country].filter(Boolean).join(' · ')],
    ['TLS issuer', t.issuer], ['Page asks for', live.content?.asks_for?.join(', ')], ['Checked', live.checked_at?.uae],
    ['Note', live.fetch_error || live.error ? 'Site unreachable from here: verdict is from the link itself' : null],
  ].filter(([, v]) => v);
  if (facts.length) box.append(h('dl', { class: 'facts live' }, facts.map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, v)))));
}
$$('[data-hunt]').forEach(b => b.addEventListener('click', async () => {
  $('#hunt-status').textContent = `Starting ${b.textContent.toLowerCase()}…`;
  try { await api('/api/hunt', { mode: b.dataset.hunt, limit: b.dataset.hunt === 'replay' ? 12 : 400 }); }
  catch (e) { $('#hunt-status').textContent = e.message; }
}));

/* ---------------- domain intelligence (Link Intelligence Engine) ---------------- */
let scanMode = 'quick';
function setMode(m) { scanMode = m; $$('#scan-form [data-mode]').forEach(b => { b.classList.toggle('on', b.dataset.mode === m); b.setAttribute('aria-checked', String(b.dataset.mode === m)); }); }
$$('#scan-form [data-mode]').forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));
$('#scan-form').addEventListener('submit', async e => {
  e.preventDefault();
  const box = $('#scan-result'), url = $('#scan-url').value.trim();
  const btn = $('#scan-form .primary'); btn.disabled = true;
  box.replaceChildren(h('div', { class: 'panel' }, h('ul', { class: 'stages' }, ['validation', 'static', 'registry', 'signatures', 'ml', ...(scanMode === 'deep' ? ['domain', 'sandbox', 'visual'] : [])]
    .map(s => h('li', { class: 'running' }, s))), h('p', { class: 'meta' }, scanMode === 'deep' ? 'Deep scan running: registration, DNS, certificate, isolated browser visit and visual check. This can take 20–40 seconds.' : 'Analysing…')));
  try {
    let r = await api('/api/v1/scan', { url, mode: scanMode });
    while (r.status === 'running') { await new Promise(res => setTimeout(res, 1500)); r = await api(`/api/v1/scan/${r.scan_id}`); }
    renderScan(r, box);
  } catch (err) { box.replaceChildren(h('div', { class: 'panel' }, h('p', {}, `Couldn’t analyse that URL: ${err.message}`))); }
  finally { btn.disabled = false; }
});
const yesNo = v => v === true ? 'Yes' : v === false ? 'No' : '–';
function kv(pairs) { return h('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== undefined && v !== null && v !== '').flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])); }
function unavailable(x) { return h('p', { class: 'meta' }, x?.reason || x?.error || 'Not available'); }
async function renderScan(r, box) {
  const reg = r.official_domain_comparison || {}, ml = r.ml_result || {}, sig = r.signature_result || {};
  const dom = r.domain_intelligence || {}, web = r.website_analysis || {}, vis = r.visual_analysis || {};
  const banner = h('div', { class: `verdict-banner ${r.verdict}` },
    h('div', {}, h('div', { class: 'vb-word' }, r.verdict), h('div', { class: 'meta' }, `${r.scan_id} · ${r.mode} scan · ${r.duration_seconds}s`)),
    h('p', { class: 'vb-why' }, r.explanation?.en || ''),
    h('dl', { class: 'vb-nums' },
      h('div', {}, h('dt', {}, 'Risk score'), h('dd', {}, r.risk_score ?? '–', h('small', { class: 'meta' }, ` ${r.risk_level}`))),
      h('div', {}, h('dt', {}, 'Confidence'), h('dd', {}, r.assessment_confidence)),
      h('div', {}, h('dt', {}, 'Completeness'), h('dd', {}, `${Math.round((r.analysis_completeness || 0) * 100)}%`, h('div', { class: 'meter' }, h('i', { style: `width:${Math.round((r.analysis_completeness || 0) * 100)}%` }))))));
  const stages = h('ul', { class: 'stages', 'aria-label': 'Pipeline stages' }, Object.entries(r.stages || {}).map(([k, v]) => h('li', { class: v }, `${k}: ${v.replace('_', ' ')}`)));
  const twin = r.twin_view ? (() => {
    const t = r.twin_view;
    return h('div', { class: 'twin' }, twinRow('This link', t.scam_segments, 'scam'), twinRow('Official', t.official_segments, 'real'),
      h('p', { class: 'twin-note' }, t.unicode_tricks.length ? `Look-alike characters: ${t.unicode_tricks.map(u => `“${u.char}” is ${u.name}`).join('; ')}.` : `${Math.round(t.similarity * 100)}% similar to the official domain.`));
  })() : null;
  const p = (title, ...kids) => h('article', { class: 'panel' }, h('h3', {}, title), ...kids);
  const rd = dom.rdap || {}, dns = dom.dns || {}, cert = dom.certificate || {};
  const related = await api(`/api/threats?q=${encodeURIComponent(r.registered_domain)}`).catch(() => []);
  box.replaceChildren(banner, stages, twin || '',
    h('div', { class: 'report-grid' },
      p('Identity', kv([['Submitted', h('span', { class: 'mono' }, r.submitted_url)], ['Normalised', h('span', { class: 'mono' }, r.normalised_url)],
        ['Final destination', r.final_url ? h('span', { class: 'mono' }, r.final_url) : r.mode === 'deep' ? 'Not reached: the site could not be visited' : 'Not followed (quick scan)'], ['Registered domain', r.registered_domain],
        ['Detected brand', r.detected_brand || 'None'], ['Official domain', reg.official_domain_match ? `Yes: ${reg.organisation} (${reg.matched_domain})` : 'No'],
        ['Closest official', reg.closest_official ? `${reg.closest_official}, similarity ${reg.similarity}` : '–']])),
      p('Machine learning', ml.available ? kv([['Prediction', ml.prediction], ['Model score', `${ml.probability} (threshold ${ml.decision_threshold}; not a calibrated probability)`],
        ['Model', ml.model_version], ['Top contributions', h('ul', {}, ml.feature_contributions.map(f => h('li', {}, `${f.description}: ${f.contribution > 0 ? '+' : ''}${f.contribution}`)))]]) : unavailable(ml)),
      p('Threat intelligence', kv([['Known threat', yesNo(sig.known_threat)], ['Sources checked', sig.sources_checked?.join(', ')],
        ['Not checked', sig.sources_skipped?.map(x => `${x.source} (${x.reason})`).join(', ')], ['Errors', Object.entries(sig.errors || {}).map(([k, v]) => `${k}: ${v}`).join('; ')]]),
        sig.matches?.length ? h('ul', { class: 'ev-list' }, sig.matches.map(m => h('li', {}, h('span', { class: 'stage' }, m.source), h('span', {}, `${m.classification}: ${m.indicator}`), h('span', { class: 'str' }, m.reference || '')))) : null),
      p('Registration and DNS', dom.available === false ? unavailable(dom) : kv([['Registrar', rd.registrar || (rd.error ? `unavailable: ${rd.error}` : '–')], ['Registered', rd.registered],
        ['Domain age', rd.age_days != null ? `${rd.age_days} days` : null], ['Nameservers', rd.nameservers?.join(', ')], ['Abuse contact', rd.abuse_contact],
        ['A records', dns.a?.join(', ') || (dns.nxdomain ? 'Domain does not resolve' : dns.error)], ['MX', dns.mx?.join(', ')], ['TXT', dns.txt?.slice(0, 3).join(' | ')]])),
      p('Certificate', !cert.available ? unavailable(cert) : cert.https === false ? h('p', {}, 'No HTTPS') : kv([['Valid', yesNo(cert.valid)], ['Issuer', cert.issuer], ['Issued', cert.not_before],
        ['Expires', cert.not_after], ['Age', cert.age_days != null ? `${cert.age_days} days` : null], ['Names', cert.subject_alt_names?.slice(0, 6).join(', ')],
        ['SHA-256', cert.fingerprint_sha256 ? h('span', { class: 'mono' }, cert.fingerprint_sha256) : null], ['Error', cert.validation_error]])),
      p('Live page (isolated browser)', !web.available ? unavailable(web) : h('div', {}, kv([['Mode', web.mode], ['HTTP status', web.http_status], ['Redirects', web.redirect_count],
        ['Page title', web.page_title], ['Password fields', web.password_fields], ['Payment fields', yesNo(web.payment_fields)], ['Email / phone fields', `${web.email_fields} / ${web.telephone_fields}`],
        ['Forms', web.forms?.map(f => `${f.method.toUpperCase()} ${f.action}${f.external ? ' (another site)' : ''}`).join('; ')], ['Third-party domains', web.third_party_domains?.slice(0, 8).join(', ')],
        ['Blocked internal requests', web.blocked_internal_requests?.length || 0], ['Downloads blocked', web.downloads_blocked?.join(', ') || 'None']]),
        web.redirect_chain?.length ? h('ol', { class: 'timeline-mini' }, web.redirect_chain.map(c => h('li', { class: 'mono' }, `${c.status} ${c.url}`))) : null,
        web.visible_text ? h('details', {}, h('summary', {}, 'Extracted text'), h('pre', { class: 'text' }, web.visible_text)) : null)),
      p('Visual impersonation', h('div', {}, vis.available ? kv([['Closest reference', vis.closest_reference], ['Perceptual', vis.perceptual_similarity], ['Layout', vis.layout_similarity],
        ['Overall', vis.overall_visual_similarity], ['Detected brand', vis.detected_brand || 'None']]) : unavailable(vis),
        vis.brand_text_found?.length ? h('p', {}, `Brand names on the page: ${vis.brand_text_found.join(', ')}`) : null,
        vis.ocr?.available ? h('details', {}, h('summary', {}, 'Text read from the screenshot (OCR)'), h('pre', { class: 'text' }, vis.ocr.text)) : null,
        h('div', { id: 'shot-slot' }))),
      p('Related records', related.length ? h('ul', { class: 'linked' }, related.slice(0, 6).map(t => h('li', {}, h('button', { class: 'ghost small', onclick: () => { show('threats'); openThreat(t.id); } }, t.id), ' ',
        pill(t.status), ` ${t.normalized} · ${t.report_count} reports · first seen ${when(t.first_seen)}`))) : h('p', { class: 'meta' }, 'No threat records for this domain yet.'),
        can('verify_threat') && r.verdict !== 'SAFE' ? h('button', { class: 'primary', onclick: async ev => { const t = await act(ev.currentTarget, () => api('/api/threats', { indicator: r.submitted_url, indicator_type: 'url', note: `Link engine ${r.verdict} ${r.risk_score} (${r.scan_id})` }), 'Threat record opened'); if (t) { show('threats'); openThreat(t.id); } } }, 'Open a threat record') : null)),
    p('Evidence', h('ul', { class: 'ev-list' }, r.evidence.map(e => h('li', { class: e.direction }, h('span', { class: 'stage' }, e.stage), h('span', {}, e.detail_en), h('span', { class: 'str' }, `${e.direction === 'trust' ? '−' : '+'}${e.strength} · ${e.reliability}`))))),
    p('Recommended action and limitations', h('p', {}, r.recommended_action.en), h('ul', { class: 'limits' }, r.limitations.map(l => h('li', {}, l)))));
  if (web.screenshot && can('view_evidence')) authedBlob(`/api/v1/scan/${r.scan_id}/screenshot`).then(u => $('#shot-slot')?.append(h('img', { class: 'shot', src: u, alt: `Screenshot of ${r.final_url}` }))).catch(() => {});
}
async function loadWatch() {
  const rows = await api('/api/intel/early-watch');
  $('#w-rows').replaceChildren(...(rows.length ? rows.slice(0, 60).map(f => {
    const b = h('button', { class: 'ghost small', onclick: () => act(b, async () => {
      const t = await api('/api/intel/early-watch/promote', { url: f.url, note: f.reason });
      b.replaceWith(h('button', { class: 'ghost small', onclick: () => { show('threats'); openThreat(t.id); } }, `Open ${t.id}`));
    }, 'Promoted to a threat record') }, 'Promote');
    return h('tr', {}, h('td', { class: 'mono' }, f.host), h('td', {}, Math.round(f.risk)), h('td', {}, f.brand || '–'), h('td', {}, f.source), h('td', {}, f.reason),
      h('td', {}, h('button', { class: 'ghost small', onclick: () => { $('#scan-url').value = f.url; scrollTo(0, 0); $('#scan-form').requestSubmit(); } }, 'Investigate'), ' ', can('verify_threat') ? b : ''));
  }) : [h('tr', {}, h('td', { colspan: 6 }, 'Nothing new on watch. Run a hunt from Live Threat Intelligence to look for new look-alike domains.'))]));
}
loaders.domain = async () => { if (can('view_investigations')) await loadWatch(); else $('#watch-panel').hidden = true; };

/* ---------------- campaigns ---------------- */
let graphMode = 'threats';
$('#g-threats').addEventListener('click', () => { graphMode = 'threats'; loaders.campaigns(); });
$('#g-kits').addEventListener('click', () => { graphMode = 'kits'; loaders.campaigns(); });
let selectedNode = null;
loaders.campaigns = async () => {
  $('#g-threats').classList.toggle('on', graphMode === 'threats');
  $('#g-kits').classList.toggle('on', graphMode === 'kits');
  if (graphMode === 'threats') {
    const g = await api('/api/intel/graph');
    $('#camp-title').textContent = 'Linked threat records';
    $('#camp-sub').textContent = 'Threats are linked when they share a domain or phishing kit, appear together in one report, or arrive as near-identical messages.';
    $('#legend').replaceChildren(...[['url', 'Website'], ['phone', 'Phone number'], ['text', 'Message'], ['email', 'Email']].map(([k, l]) => h('span', {}, h('i', { class: `dot k-${k}`, style: `background:${KCOL[k]}` }), l)));
    $('#camp-list').replaceChildren(...(g.campaigns.length ? g.campaigns.map(c => {
      const li = h('li', { tabindex: 0, onclick: () => { selectedNode = c.threats[0]; $$('#camp-list li').forEach(x => x.classList.remove('sel')); li.classList.add('sel'); } },
        h('div', { class: 'kit-sig' }, c.id), h('div', { class: 'camp-meta' }, `${c.threats.length} linked threats · ${c.types.join(', ')}${c.brands.length ? ' · ' + c.brands.join(', ') : ''}`),
        h('div', { class: 'camp-meta' }, c.threats.slice(0, 5).join(', ')));
      return li;
    }) : [h('li', {}, 'No linked campaigns yet. They form as reports share links, numbers, kits or wording.')]));
    const nodes = g.graph.nodes.map(n => ({ id: n.id, kind: n.kind === 'domain' || n.kind === 'qr' ? 'url' : n.kind, label: `${n.id} ${n.label}` }));
    startGraph({ nodes, edges: g.graph.edges }, n => KCOL[n.kind] || '#A7B4C6', () => 6, n => n.id === selectedNode || nodes.length <= 25);
  } else {
    const c = await api('/api/campaigns');
    $('#camp-title').textContent = 'Kits reused across domains';
    $('#camp-sub').textContent = 'From public phishing feeds: same file names and folders on different domains = same operation.';
    $('#legend').replaceChildren(h('span', {}, h('i', { class: 'dot kit' }), 'Phishing kit'), h('span', {}, h('i', { class: 'dot brand' }), 'UAE brand'), h('span', {}, h('i', { class: 'dot domain' }), 'Scam domain'));
    $('#camp-list').replaceChildren(...c.campaigns.map(x => {
      const li = h('li', { tabindex: 0, onclick: () => { selectedNode = 'kit:' + x.id; $$('#camp-list li').forEach(y => y.classList.remove('sel')); li.classList.add('sel'); } },
        h('div', { class: 'kit-sig' }, x.kit_signature), h('div', { class: 'camp-meta' }, `${x.domains.length} domains · ${x.url_count} URLs · ${x.brands.join(', ')}`));
      return li;
    }));
    startGraph(c.graph, n => n.kind === 'brand' ? '#F1E9DC' : n.kind === 'kit' ? '#E8A33D' : '#7DB8E8', n => n.kind === 'brand' ? 14 : n.kind === 'kit' ? 9 : 5, n => n.kind === 'brand');
  }
};
const KCOL = { url: '#7DB8E8', phone: '#E8A33D', text: '#C9B98F', email: '#F1E9DC' };

let sim = null;
function startGraph(g, colorFn, radiusFn, alwaysLabel) {
  const cv = $('#graph'), ctx = cv.getContext('2d');
  const fit = () => { const r = cv.getBoundingClientRect(), d = devicePixelRatio || 1; cv.width = r.width * d; cv.height = r.height * d; ctx.setTransform(d, 0, 0, d, 0, 0); };
  fit(); addEventListener('resize', fit);
  const W = () => cv.getBoundingClientRect().width, H = () => cv.getBoundingClientRect().height;
  const nodes = g.nodes.map((n, i) => ({ ...n, x: W() / 2 + Math.cos(i) * 200 * Math.random(), y: H() / 2 + Math.sin(i) * 200 * Math.random(), vx: 0, vy: 0 }));
  const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
  const links = g.edges.map(e => ({ s: byId[e.source], t: byId[e.target] })).filter(l => l.s && l.t);
  let hover = null, ticks = 0;
  cv.onmousemove = e => { const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top; hover = nodes.find(n => (n.x - x) ** 2 + (n.y - y) ** 2 < 120) || null; };
  cv.onclick = () => { if (hover) { selectedNode = hover.id; if (graphMode === 'threats' && hover.id.startsWith('RQ-')) { show('threats'); openThreat(hover.id); } } };
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
    const focus = hover?.id || selectedNode;
    const linked = new Set();
    if (focus) links.forEach(l => { if (l.s.id === focus || l.t.id === focus) { linked.add(l.s.id); linked.add(l.t.id); } });
    for (const l of links) {
      const on = focus && (l.s.id === focus || l.t.id === focus);
      ctx.strokeStyle = on ? 'rgba(232,163,61,.9)' : 'rgba(167,180,198,.25)'; ctx.lineWidth = on ? 1.6 : 1;
      ctx.beginPath(); ctx.moveTo(l.s.x, l.s.y); ctx.lineTo(l.t.x, l.t.y); ctx.stroke();
    }
    for (const n of nodes) {
      ctx.globalAlpha = focus && !linked.has(n.id) && n.id !== focus ? 0.3 : 1;
      ctx.fillStyle = colorFn(n);
      const r = radiusFn(n);
      ctx.beginPath();
      if (n.kind === 'kit') { ctx.moveTo(n.x, n.y - r); ctx.lineTo(n.x + r, n.y); ctx.lineTo(n.x, n.y + r); ctx.lineTo(n.x - r, n.y); ctx.closePath(); }
      else ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fill();
      if (alwaysLabel(n) || n.id === focus || linked.has(n.id) || n === hover) {
        ctx.fillStyle = '#F1E9DC'; ctx.font = n.kind === 'brand' ? '600 14px Cairo, sans-serif' : '12.5px "Readex Pro", sans-serif';
        const lab = n.label || n.id;
        ctx.fillText(lab.length > 46 ? lab.slice(0, 44) + '…' : lab, n.x + r + 6, n.y + 4);
      }
    }
    ctx.globalAlpha = 1;
    sim = requestAnimationFrame(frame);
  };
  frame();
}

/* ---------------- forecast ---------------- */
loaders.forecast = async () => {
  const f = await api('/api/intel/forecast');
  const col = (cls, title, sub, items) => h('article', { class: cls }, h('h3', {}, title), h('p', { class: 'note' }, sub), h('ul', {}, items.length ? items : [h('li', {}, 'Nothing in this class right now.')]));
  $('#fc-cols').replaceChildren(
    col('confirmed', 'Confirmed now', 'Analyst-confirmed in the last 30 days', f.confirmed_current.map(c => h('li', {}, `${catLabel(c.category)}: ${c.n}`))),
    col('observed', 'Emerging', 'Citizen reports rising week over week (not yet confirmed)', f.observed_emerging.map(o => h('li', {}, `${META.report_types[o.report_type] || o.report_type}: ${o.last_week} → ${o.this_week}`))),
    col('predicted', 'Predicted', 'Forecasts from seasonal patterns. Not scams that exist.', f.predicted.map(p => h('li', {}, p.season, p.advice ? h('div', { class: 'meta' }, p.advice) : p.watchlist ? h('div', { class: 'meta' }, `Watching e.g. ${p.watchlist.slice(0, 2).join(', ')}`) : null))),
    col('historical', 'Historical pattern', 'What usually happens in each season', f.historical_associations.map(x => h('li', {}, `${x.season}: ${x.categories.map(catLabel).join(', ')}`))));
  $('#seasons').replaceChildren(...f.scamcast.map(x => h('article', { class: 'season' },
    h('h3', {}, x.name), h('p', { class: 'ar', lang: 'ar' }, x.name_ar),
    h('p', { class: 'meta' }, `Watching ${x.watchlist_size} possible look-alike domains (forecast, not confirmed)`),
    h('ul', {}, x.sample.slice(0, 5).map(d => h('li', {}, d))),
    can('run_hunt') ? h('button', { class: 'primary', onclick: async () => { show('feed'); $('#hunt-status').textContent = `Checking which of these exist: ${x.name}…`; await api('/api/hunt', { mode: 'scamcast', season: x.id }); } }, 'Check which ones exist now') : null)));
};

/* ---------------- briefing ---------------- */
let bPeriod = 'day';
$$('#b-period [data-p]').forEach(b => b.addEventListener('click', () => { bPeriod = b.dataset.p; loaders.briefing(); }));
$('#b-print').addEventListener('click', () => print());
loaders.briefing = async () => {
  $$('#b-period [data-p]').forEach(b => b.classList.toggle('on', b.dataset.p === bPeriod));
  const b = await api(`/api/intel/briefing?period=${bPeriod}`);
  const list = (title, items, fn) => [h('h3', { class: 'section-h' }, title), h('ul', {}, items.length ? items.map(i => h('li', {}, fn(i))) : [h('li', {}, 'None.')])];
  $('#b-body').replaceChildren(
    h('p', { class: 'meta' }, `Generated ${when(b.generated)} · ${b.summary_source === 'llm' ? 'written by the configured AI model from RAQEEB data' : 'written by RAQEEB’s rule-based briefing agent'}`),
    h('p', {}, b.summary),
    h('dl', { class: 'kpis' }, [['New threats', b.new_threats], ['Confirmed', b.confirmed], ['Citizen reports', b.citizen_reports], ['Awaiting review', b.awaiting_review], ['Awaiting block decision', b.awaiting_block_approval], ['Blocked now', b.blocked_now]]
      .map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, v)))),
    ...list('Recommended actions', b.recommended_actions, x => x),
    ...list('Most impersonated', b.top_brands, x => `${x.brand}: ${x.n}`),
    ...list('Top categories', b.top_categories, x => `${catLabel(x.category)}: ${x.n}`),
    ...list('Largest campaigns', b.campaigns, x => `${x.campaign_id}: ${x.n} linked threats`));
};

/* ---------------- agents ---------------- */
const AGENT_INFO = {
  threat_hunter: 'Finds new look-alike domains and certificates', phishing_intelligence: 'Scores websites and explains why',
  message_intelligence: 'Reads SMS, WhatsApp and email scripts', advertisement_intelligence: 'Spots fake offers, jobs and investments',
  phone_intelligence: 'Checks numbers against past reports', campaign_correlation: 'Links threats into campaigns',
  seasonal_intelligence: 'Forecasts seasonal scam waves', community_intelligence: 'Spots duplicates and report abuse',
  intelligence_briefing: 'Writes daily, weekly and monthly briefings', protection_distribution: 'Queues confirmed threats for approval',
};
loaders.agents = async () => {
  const [list, rows] = await Promise.all([api('/api/intel/agents'), api('/api/intel/findings')]);
  const llm = list.find(x => 'llm_enabled' in x);
  $('#a-list').replaceChildren(...list.filter(x => x.id).map(a => h('div', {}, h('b', {}, a.id.replace(/_/g, ' ')), h('span', { class: 'meta' }, AGENT_INFO[a.id]), h('div', { class: 'meta' }, `${a.findings} findings recorded`))),
    h('div', {}, h('b', {}, 'Optional AI model'), h('span', { class: 'meta' }, llm?.llm_enabled ? 'Connected: briefings are written by the configured model.' : 'Not configured. Everything runs on RAQEEB’s own code.')));
  $('#a-rows').replaceChildren(...rows.slice(0, 80).map(f => h('tr', {}, h('td', {}, f.agent.replace(/_/g, ' ')), h('td', {}, f.subject), h('td', {}, `${Math.round(f.confidence * 100)}%`),
    h('td', {}, f.reasoning), h('td', {}, f.next_action || '–'), h('td', {}, ago(f.created)))));
};

/* ---------------- protection ---------------- */
loaders.protection = async () => {
  const [pkg, versions] = await Promise.all([api('/api/protection/latest'), api('/api/protection/versions')]);
  const rules = pkg.payload.rules;
  $('#p-kpis').replaceChildren(...[['Current version', `v${pkg.payload.version}`], ['Rules', rules.length], ['Domain rules', rules.filter(r => r.type === 'domain').length],
    ['URL or host rules', rules.filter(r => r.type === 'url' || r.type === 'host').length], ['Phone rules', rules.filter(r => r.type === 'phone').length], ['Signature', 'Ed25519']]
    .map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, v))));
  $('#p-rules').replaceChildren(...(rules.length ? rules.map(r => h('tr', {}, h('td', {}, r.type), h('td', {}, r.value),
    h('td', {}, r.threat_id ? h('button', { class: 'ghost small', onclick: () => { show('threats'); openThreat(r.threat_id); } }, r.threat_id) : '1.0 blocklist'),
    h('td', {}, r.brand || '–'), h('td', {}, r.expires ? when(r.expires) : '–'))) : [h('tr', {}, h('td', { colspan: 5 }, 'No rules yet. Confirm a threat and approve a global block to publish one.'))]));
  $('#p-versions').replaceChildren(...versions.map(v => h('tr', {}, h('td', {}, `v${v.version}${v.rolled_back ? ' (rolled back)' : ''}`), h('td', {}, when(v.created)), h('td', {}, v.published_by), h('td', {}, v.rule_count), h('td', {}, v.notes))));
};
$('#p-rollback').addEventListener('click', e => {
  if (!confirm('Roll back the latest protection version for every user? This publishes a new version with the previous rules.')) return;
  act(e.currentTarget, async () => { await api('/api/protection/rollback', {}); loaders.protection(); loadCounters(); }, 'Rolled back and republished');
});

/* ---------------- community ---------------- */
loaders.community = async () => {
  const [abuse, board] = await Promise.all([api('/api/community/abuse'), api('/api/public/leaderboard?period=week')]);
  $('#cm-abuse').replaceChildren(...(abuse.length ? abuse.map(u => h('tr', {}, h('td', {}, u.display_name), h('td', {}, u.emirate || '–'), h('td', {}, u.reputation.toFixed(2)), h('td', {}, u.reports_24h), h('td', {}, u.rejected)))
    : [h('tr', {}, h('td', { colspan: 5 }, 'No accounts need review.'))]));
  $('#cm-board').replaceChildren(...(board.guardians.length ? board.guardians.map(g => h('li', {}, h('b', {}, g.display_name), ` · ${g.level} · ${g.pts} pts · ${g.emirate || ''}`)) : [h('li', {}, 'No verified contributions this week yet.')]));
};

/* ---------------- audit + users ---------------- */
loaders.audit = async () => {
  const rows = await api('/api/audit');
  $('#au-rows').replaceChildren(...rows.map(a => h('tr', {}, h('td', {}, when(a.ts)), h('td', {}, a.actor || 'system'), h('td', {}, a.action), h('td', {}, a.detail))));
};
loaders.users = async () => {
  const orgs = await api('/api/v1/organizations');
  $('#org-rows').replaceChildren(...orgs.map(o => h('tr', {}, h('td', {}, o.name, h('div', { class: 'meta', lang: 'ar' }, o.name_ar || '')), h('td', {}, o.sector),
    h('td', {}, o.domains.map(d => h('div', { class: 'mono' }, d.domain, ' ', h('span', { class: `pill ${d.status === 'verified' ? 'resolved' : 'demo'}` }, d.status === 'verified' ? 'verified' : 'unverified')))),
    h('td', {}, o.origin))));
  if (!can('manage_users')) return;
  const users = await api('/api/admin/users');
  const roles = ['super_admin', 'police_admin', 'cyber_analyst', 'investigation_officer', 'intel_analyst', 'supervisor', 'citizen'];
  $('#u-role').replaceChildren(...roles.filter(r => r !== 'citizen').map(r => h('option', { value: r }, r.replace(/_/g, ' '))));
  $('#u-rows').replaceChildren(...users.filter(u => u.role !== 'citizen').map(u => {
    const sel = h('select', { 'aria-label': `Role for ${u.email}`, disabled: u.id === ME.id, onchange: async () => { await api(`/api/admin/users/${u.id}`, { role: sel.value }, 'PATCH'); toast('Role changed', u.email); } },
      roles.map(r => h('option', { value: r, selected: r === u.role }, r.replace(/_/g, ' '))));
    const dis = h('button', { class: 'ghost small', disabled: u.id === ME.id, onclick: async () => { await api(`/api/admin/users/${u.id}`, { disabled: !u.disabled }, 'PATCH'); loaders.users(); } }, u.disabled ? 'Enable' : 'Disable');
    return h('tr', {}, h('td', {}, u.display_name), h('td', {}, u.email), h('td', {}, sel), h('td', {}, u.disabled ? 'Disabled' : 'Active'), h('td', {}, dis));
  }));
};
$('#org-form').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await api('/api/v1/organizations', { name: $('#org-name').value, domains: $('#org-domains').value.split(',').map(x => x.trim()).filter(Boolean), verification_source: $('#org-source').value || null });
    $('#org-form').reset(); loaders.users(); toast('Organisation saved');
  } catch (err) { toast('Couldn’t save the organisation', err.message); }
});

/* ---------------- demo scenario ---------------- */
const STEP_WHO = { verify: 'Analyst: Threat Verification', approve: 'Official: Threat Verification', distribute: 'Official: approve global block',
  citizen_check: 'Citizen: paste the link in PROTECT', community: 'Citizen: report the advert in PROTECT', command_update: 'Analyst: verify the new report' };
loaders.demo = async () => {
  const st = await api('/api/demo/status');
  $('#demo-steps').replaceChildren(...st.steps.map(s => h('li', { class: s.done ? 'done' : '' }, h('span', {}, s.title), h('span', { class: 'who-does' }, s.done ? 'Done' : STEP_WHO[s.id] || 'Automatic (steps 1–5)'))));
  const sc = st.scenario;
  const copy = (label, text) => [h('p', { class: 'meta' }, label), h('div', { class: 'copy' }, h('pre', { class: 'text' }, text),
    h('button', { class: 'ghost small', onclick: () => { navigator.clipboard?.writeText(text); toast('Copied'); } }, 'Copy'))];
  $('#demo-kit').replaceChildren(h('h3', {}, 'Presenter kit'),
    st.threat_id ? h('p', {}, 'Main threat: ', h('button', { class: 'ghost small', onclick: () => { show('threats'); openThreat(st.threat_id); } }, st.threat_id),
      st.campaign_id ? ` · campaign ${st.campaign_id}` : '') : h('p', { class: 'meta' }, 'Run steps 1–5 to create the scenario.'),
    ...copy('Step 9: the citizen pastes this payment link in PROTECT', sc.payment_link),
    ...copy('Step 10: the citizen reports this advertisement in PROTECT (type: Scam advertisement)', sc.ad_text),
    h('p', { class: 'meta' }, 'All domains, numbers and messages in this scenario are invented for the demonstration and marked as demo data.'));
};
$('#demo-seed').addEventListener('click', e => act(e.currentTarget, async () => { await api('/api/demo/seed', {}); loaders.demo(); loadCounters(); }, 'Steps 1–5 done'));
$('#demo-reset').addEventListener('click', e => {
  if (!confirm('Remove all demo-seeded records and demo-account activity? Real data is not touched.')) return;
  act(e.currentTarget, async () => { await api('/api/demo/reset', {}); loaders.demo(); loadCounters(); }, 'Demo data removed');
});

$('#u-form').addEventListener('submit', async e => {
  e.preventDefault();
  try { await api('/api/admin/users', { email: $('#u-email').value, password: $('#u-pass').value, role: $('#u-role').value }); $('#u-form').reset(); loaders.users(); toast('Account added'); }
  catch (err) { toast('Couldn’t add the account', err.message); }
});

/* ---------------- phones modal ---------------- */
$('#btn-phones').addEventListener('click', async () => {
  const { url } = await api('/api/join-url');
  $('#qr').src = `/api/qr?data=${encodeURIComponent(url)}`;
  $('#join-url').textContent = url;
  $('#phones').hidden = false;
});
$('#phones-close').addEventListener('click', () => { $('#phones').hidden = true; });

/* ---------------- live socket ---------------- */
let socket = null;
function connect() {
  if (!TOKEN) return;
  socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
  socket.onopen = () => { $('#live').className = 'live on'; $('#live').textContent = 'Live'; };
  socket.onclose = () => { $('#live').className = 'live off'; $('#live').textContent = 'Reconnecting'; if (TOKEN) setTimeout(connect, 2000); };
  socket.onmessage = ev => {
    const { event, data } = JSON.parse(ev.data);
    if (event === 'feed') {
      const f = { url: data.url, host: data.url.replace(/^https?:\/\//, '').split('/')[0], brand: data.brand, risk: data.risk, verdict: data.verdict, source: data.source, ts: Date.now() / 1000 };
      FEED.unshift(f);
      if (onView('feed') && (!brandFilter || brandFilter === f.brand)) $('#feed').prepend(feedItem(f, true));
    } else if (event === 'hunt') {
      $('#hunt-status').textContent = data.status === 'started' ? `Hunting (${data.mode})…` : `Done: checked ${data.checked}, ${data.found} live, ${data.flagged} flagged.`;
    } else if (event === 'citizen_report') {
      toast(`New citizen report ${data.ref}`, `${META.report_types[data.type] || data.type}${data.emirate ? ' · ' + data.emirate : ''} · risk ${Math.round(data.risk || 0)}`);
      loadCounters();
      if (onView('reports')) loaders.reports();
      if (onView('threats')) loaders.threats();
      if (onView('overview')) loaders.overview();
    } else if (event === 'threat') {
      loadCounters();
      if (onView('threats')) loaders.threats();
    } else if (event === 'protection') {
      toast(`Protection v${data.version} published`, `${data.rules} rules now on every RAQEEB device`);
      loadCounters();
      if (onView('protection')) loaders.protection();
    }
  };
}

loadDemoLogins().then(() => { if (TOKEN) start(); });
