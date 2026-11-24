// RAQEEB Protect 2.0 (installable web app). All text from the network is inserted with textContent.
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

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

let lang = localStorage.getItem('raqeeb-lang') || 'en';
let TOKEN = localStorage.getItem('raqeeb_token');
let ME = null, META = null, PROFILE = null;
const t = (k, ...a) => { const v = T[lang][k]; return typeof v === 'function' ? v(...a) : v; };
const typeLabel = k => lang === 'ar' ? TYPE_AR[k] : META?.report_types[k] || k;
const statusLabel = s => lang === 'ar' ? STATUS_AR[s] || s : META?.statuses[s] || s;
const emirateLabel = e => lang === 'ar' ? EMIRATE_AR[e] || e : e;
const sevLabel = s => lang === 'ar' ? SEVERITY_AR[s] || s : s;
const fmtDate = ts => new Date(ts * 1000).toLocaleString(lang === 'ar' ? 'ar-AE' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' });

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  let body = opts.body;
  if (body && !(body instanceof FormData)) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(body); }
  const r = await fetch(path, { method: opts.method || (body ? 'POST' : 'GET'), headers, body });
  if (r.status === 401 && TOKEN) { setToken(null); }
  if (!r.ok) {
    let msg = String(r.status);
    try { msg = (await r.json()).detail || msg; } catch { /* not JSON */ }
    const e = new Error(Array.isArray(msg) ? msg.map(x => x.msg).join('; ') : msg); e.status = r.status; throw e;
  }
  return r.json();
}
function setToken(tok) {
  TOKEN = tok;
  if (tok) localStorage.setItem('raqeeb_token', tok); else localStorage.removeItem('raqeeb_token');
}

function banner(title, text, ms = 6000) {
  const el = $('#banner');
  el.replaceChildren(title ? h('b', {}, title) : '', text || '');
  el.hidden = false;
  clearTimeout(banner.tm);
  banner.tm = setTimeout(() => { el.hidden = true; }, ms);
}

/* ---------------- language ---------------- */
function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  $$('[data-i]').forEach(el => { const v = t(el.dataset.i); if (typeof v === 'string') el.textContent = v; });
  $$('[data-ph]').forEach(el => { el.placeholder = t(el.dataset.ph); });
  $('#lang').textContent = lang === 'ar' ? 'English' : 'عربي';
  fillEmirates();
  renderTypes();
  renderShield();
  renderAlerts();
  if (BRANDS) renderBrands();
  syncAuthForm();
  for (const fn of [loadSeason, loadMyReports, loadBlocks, loadFamily, loadCommunity, loadProfile]) fn().catch(() => {});
}
$('#lang').addEventListener('click', () => { lang = lang === 'ar' ? 'en' : 'ar'; localStorage.setItem('raqeeb-lang', lang); applyLang(); });

/* ---------------- tabs ---------------- */
function go(tab) {
  $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === tab));
  $$('.tab').forEach(x => x.classList.toggle('on', x.id === `t-${tab}`));
  scrollTo(0, 0);
  ({ protect: () => { loadBlocks(); loadFamily(); }, report: loadMyReports, community: loadCommunity, profile: loadProfile }[tab])?.();
}
$$('.tabs button').forEach(b => b.addEventListener('click', () => go(b.dataset.tab)));
$$('[data-goto]').forEach(b => b.addEventListener('click', () => go(b.dataset.goto)));

function fillEmirates() {
  if (!META) return;
  for (const id of ['#r-emirate', '#a-emirate', '#s-emirate']) {
    const sel = $(id), cur = sel.value || ME?.emirate || 'Abu Dhabi';
    sel.replaceChildren(...META.emirates.map(e => h('option', { value: e, selected: e === cur }, emirateLabel(e))));
  }
  const lb = $('#lb-emirate'), cur = lb.value;
  lb.replaceChildren(h('option', { value: '' }, t('allEmirates')), ...META.emirates.map(e => h('option', { value: e, selected: e === cur }, emirateLabel(e))));
}

/* ---------------- signed protection package (works offline) ---------------- */
let PKG = JSON.parse(localStorage.getItem('raqeeb_pkg') || 'null');
let SIG_STATE = localStorage.getItem('raqeeb_sig') || 'sigServer';
let ONLINE = true;
function canonical(v) {  // same bytes as the server: sorted keys, no spaces, UTF-8
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
async function verifyPackage(pkg) {
  try {
    const { public_key } = await api('/api/protection/public-key');
    const raw = Uint8Array.from(atob(public_key), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    const sig = Uint8Array.from(atob(pkg.signature), c => c.charCodeAt(0));
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, new TextEncoder().encode(canonical(pkg.payload))) ? 'sigOk' : 'sigBad';
  } catch { return 'sigServer'; }  // this browser has no Ed25519 in WebCrypto (or no secure context)
}
async function syncProtection() {
  try {
    const pkg = await api('/api/protection/latest');
    ONLINE = true;
    if (PKG && pkg.payload.version === PKG.payload.version) { renderShield(); return; }
    const state = await verifyPackage(pkg);
    if (state === 'sigBad') { SIG_STATE = 'sigBad'; renderShield(); return; }
    PKG = pkg; SIG_STATE = state;
    localStorage.setItem('raqeeb_pkg', JSON.stringify(pkg)); localStorage.setItem('raqeeb_sig', state);
  } catch { ONLINE = false; }
  renderShield();
}
function renderShield() {
  const rules = activeRules();
  $('#shield').classList.toggle('offline', !ONLINE);
  $('#shield-state').textContent = ONLINE ? t('shieldOn') : t('shieldOffline');
  $('#shield-meta').textContent = PKG ? t('shieldMeta', PKG.payload.version, rules.length, t(SIG_STATE)) : '';
}
const activeRules = () => (PKG?.payload.rules || []).filter(r => !r.expires || r.expires > Date.now() / 1000);
function hostOf(s) {
  try { return new URL(/^[a-z]+:\/\//i.test(s) ? s : 'http://' + s).hostname.replace(/^www\./, '').toLowerCase(); } catch { return ''; }
}
function localRule(input) {
  const s = input.trim();
  const host = hostOf(s);
  let path = '';
  try { const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : 'http://' + s); path = host + u.pathname.replace(/\/$/, '') + u.search; } catch { /* not a URL */ }
  const digits = s.replace(/[^\d+]/g, '');
  return activeRules().find(r =>
    (r.type === 'url' && path.startsWith(r.value)) ||
    ((r.type === 'domain' || r.type === 'host') && host && (host === r.value || host.endsWith('.' + r.value))) ||
    (r.type === 'phone' && digits.length > 7 && r.value.endsWith(digits.replace(/^0+/, '').slice(-9))));
}

/* ---------------- checking ---------------- */
const looksLikeLink = s => !/\s/.test(s.trim()) && /[.]/.test(s);
let lastInput = '', lastResult = null;
$('#check-form').addEventListener('submit', e => { e.preventDefault(); check($('#input').value); });
async function check(raw) {
  const text = (raw || '').trim();
  if (!text) { banner('', t('empty'), 3000); return; }
  lastInput = text;
  const btn = $('#check-form .go'); btn.textContent = t('checking'); btn.disabled = true;
  const rule = localRule(text);
  try {
    let r;
    if (looksLikeLink(text)) {
      const link = await api(`/api/check?url=${encodeURIComponent(text)}`);
      r = { kind: 'link', verdict: link.blocked ? 'blocked' : link.verdict === 'phishing' ? 'scam' : link.verdict, link, reasons: link.reasons };
    } else {
      const m = await api('/api/check-message', { body: { text } });
      const worst = [...m.links].sort((a, b) => b.risk_score - a.risk_score)[0];
      r = { kind: 'message', verdict: m.links.some(l => l.blocked) ? 'blocked' : m.verdict === 'looks safe' ? 'safe' : m.verdict, link: worst, msg: m,
            reasons: [...m.script_signals, ...(worst ? worst.reasons : [])] };
    }
    if (rule && r.verdict !== 'blocked') r.verdict = 'blocked';
    lastResult = r;
    showVerdict(r);
  } catch {
    ONLINE = false; renderShield();
    if (rule) showVerdict({ verdict: 'blocked', reasons: [], offline: true });
    else banner('', t('offline'));
  } finally { btn.textContent = t('checkBtn'); btn.disabled = false; }
}
function seg(segs) {
  return h('span', { class: 'host' }, segs.map(s => s.type === 'same' ? s.text : h('span', { class: s.type }, s.text)));
}
function showVerdict(r) {
  const sheet = $('#verdict');
  const tone = r.verdict === 'blocked' ? 'scam' : r.verdict;
  sheet.className = `sheet ${tone}`;
  $('#v-word').textContent = r.verdict === 'blocked' ? t('blockedEveryone') : t(r.verdict);
  const b = r.link?.impersonated_brand;
  $('#v-brand').textContent = b ? t('pretends', lang === 'ar' ? b.name_ar : b.name) : '';
  const twin = $('#v-twin'); twin.replaceChildren();
  if (b?.twin) {
    twin.append(h('div', { class: 'row' }, h('span', { class: 'lbl' }, t('thisLink')), seg(b.twin.scam_segments)),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, t('official')), seg(b.twin.official_segments)),
      h('p', { class: 'note' }, b.twin.unicode_tricks.length ? t('unicodeNote', b.twin.unicode_tricks[0]) : t('similar', Math.round(b.twin.similarity * 100))));
  }
  const seen = new Set();
  const reasons = (r.verdict === 'blocked' ? [t('blockedRule')] : []).concat(
    (r.reasons || []).map(x => x[lang]).filter(x => x && !seen.has(x) && seen.add(x)).slice(0, 5));
  $('#v-reasons').replaceChildren(...reasons.map(txt => h('li', {}, txt)));
  $('#v-advice').textContent = r.msg && r.verdict !== 'blocked' ? r.msg[`advice_${lang}`] : t(tone === 'scam' ? 'adviceScam' : tone === 'suspicious' ? 'adviceWarn' : 'adviceSafe');
  $('#v-block').textContent = t('blockForMe'); $('#v-block').disabled = false;
  sheet.hidden = false; sheet.scrollTop = 0;
  if (tone === 'scam') navigator.vibrate?.([120, 60, 120]);
}
$('#v-close').addEventListener('click', () => { $('#verdict').hidden = true; });
$('#v-report').addEventListener('click', () => {
  $('#verdict').hidden = true;
  $('#r-text').value = lastInput;
  selectType(lastResult?.kind === 'link' ? 'website' : 'auto');
  go('report');
  $('#r-text').focus();
});
$('#v-block').addEventListener('click', async () => {
  if (!TOKEN) { banner('', t('signInFirst')); return; }
  const target = lastResult?.link?.host || lastInput;
  try { await api('/api/citizen/blocks', { body: { value: target } }); $('#v-block').textContent = t('blockedForMe'); $('#v-block').disabled = true; }
  catch (e) { banner('', e.message); }
});

/* QR codes (fake parking and payment stickers) */
let stream = null;
$('#qr-btn').addEventListener('click', async () => {
  if (!('BarcodeDetector' in window)) { banner('', t('noQr')); return; }
  const det = new BarcodeDetector({ formats: ['qr_code'] });
  try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } }); }
  catch { banner('', t('noQr')); return; }
  const v = $('#qr-video'); v.srcObject = stream; await v.play(); $('#qr-box').hidden = false;
  const tick = async () => {
    if (!stream) return;
    const codes = await det.detect(v).catch(() => []);
    if (codes.length) { stopQr(); banner('', t('qrFound'), 2500); $('#input').value = codes[0].rawValue; check(codes[0].rawValue); return; }
    requestAnimationFrame(tick);
  };
  tick();
});
function stopQr() { stream?.getTracks().forEach(x => x.stop()); stream = null; $('#qr-box').hidden = true; }
$('#qr-stop').addEventListener('click', stopQr);

/* ---------------- home: confirmed alerts + season ---------------- */
let ALERTS = [], freshAlert = null;
async function loadAlerts() { try { ALERTS = await api('/api/public/alerts'); } catch { ALERTS = []; } renderAlerts(); }
function renderAlerts() {
  const ol = $('#alerts');
  if (!ALERTS.length) { ol.replaceChildren(h('li', { class: 'empty' }, t('noAlerts'))); return; }
  ol.replaceChildren(...ALERTS.slice(0, 8).map(a => h('li', { class: a.id === freshAlert ? 'new' : '' },
    h('b', { class: 'ltr' }, a.normalized), h('span', {}, [a.brand ? t('pretends', a.brand) : '', META ? (lang === 'ar' ? '' : META.categories[a.category]) : ''].filter(Boolean).join(' · ')),
    h('div', { class: 'when' }, fmtDate(a.last_seen)))));
}
async function loadSeason() {
  const f = await api('/api/public/forecast');
  const items = f.predicted.filter(p => p.season).slice(0, 4);
  $('#season-card').hidden = !items.length;
  $('#season-list').replaceChildren(...items.map(p => h('li', {}, lang === 'ar' ? p.season_ar || p.season : p.season, p.advice && lang === 'en' ? h('div', { class: 'hint' }, p.advice) : null)));
}

/* ---------------- protect tab ---------------- */
$('#preview-form').addEventListener('submit', async e => {
  e.preventDefault();
  const out = $('#preview-out');
  out.replaceChildren(h('p', { class: 'hint' }, t('checking')));
  try {
    const p = await api(`/api/preview?url=${encodeURIComponent($('#preview-url').value)}`);
    const tone = p.risk >= 70 ? 'scam' : p.risk >= 40 ? 'suspicious' : 'safe';
    out.replaceChildren(h('p', { class: `pv-verdict ${tone}` }, t(tone), ` · ${Math.round(p.risk)} / 100`),
      p.final_url ? h('p', {}, h('b', {}, `${t('goesTo')}: `), h('span', { class: 'ltr' }, p.final_url)) : null,
      p.chain ? h('p', { class: 'hint' }, t('hops', Math.max(0, p.chain.length - 1))) : null,
      p.title ? h('p', {}, h('b', {}, `${t('pageTitle')}: `), p.title) : null,
      p.brand ? h('p', {}, t('pretends', p.brand)) : null,
      h('ul', {}, (p.reasons || []).slice(0, 3).map(x => h('li', {}, x[lang]))),
      p.error ? h('p', { class: 'hint' }, p.error) : null);
  } catch (err) { out.replaceChildren(h('p', { class: 'error' }, err.message)); }
});
async function loadBlocks() {
  const ul = $('#myblocks');
  if (!TOKEN) { ul.replaceChildren(h('li', { class: 'hint' }, t('signInFirst'))); return; }
  const rows = await api('/api/citizen/blocks');
  ul.replaceChildren(...(rows.length ? rows.map(b => h('li', { class: 'row-item' }, h('span', { class: 'ltr' }, b.value),
    h('button', { class: 'link', onclick: async () => { await api(`/api/citizen/blocks?value=${encodeURIComponent(b.value)}`, { method: 'DELETE' }); loadBlocks(); } }, t('unblock'))))
    : [h('li', { class: 'hint' }, t('noBlocks'))]));
}
$('#myblock-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (!TOKEN) { banner('', t('signInFirst')); return; }
  try { await api('/api/citizen/blocks', { body: { value: $('#myblock-value').value } }); $('#myblock-value').value = ''; loadBlocks(); }
  catch (err) { banner('', err.message); }
});
let BRANDS = null;
async function loadBrands() { BRANDS = await api('/api/public/brands'); renderBrands(); }
function renderBrands() {
  const q = $('#brand-search').value.trim().toLowerCase();
  const list = BRANDS.filter(b => !q || (b.name + ' ' + b.name_ar + ' ' + b.official_domains.map(d => d.domain).join(' ')).toLowerCase().includes(q)).slice(0, q ? 12 : 6);
  $('#brands').replaceChildren(...list.map(b => h('li', {},
    h('b', {}, lang === 'ar' ? b.name_ar : b.name),
    h('div', { class: 'domains' }, b.official_domains.map(d => h('span', { class: 'ltr dom' }, d.domain, d.verified ? '' : ` (${t('unverified')})`))),
    h('p', { class: 'hint' }, lang === 'ar' ? b.contact_rule_ar : b.contact_rule_en))));
}
$('#brand-search').addEventListener('input', () => BRANDS && renderBrands());

$('#simulate').addEventListener('click', () => {
  if (!$('#oncall').checked) { banner('', t('guardOff')); return; }
  setTimeout(() => { $('#takeover').hidden = false; navigator.vibrate?.([300, 100, 300, 100, 300]); }, 900);
});
$('#to-deny').addEventListener('click', () => { $('#takeover').hidden = true; banner('', t('declined'), 8000); });
$('#to-allow').addEventListener('click', () => { $('#takeover').hidden = true; });

async function loadFamily() {
  const box = $('#family');
  if (!TOKEN) { box.replaceChildren(h('p', { class: 'hint' }, t('signInFirst'))); return; }
  const fam = PROFILE?.family ?? (await api('/api/citizen/profile')).family;
  if (!fam) {
    const name = h('input', { placeholder: t('familyNamePh'), maxlength: 40 }), code = h('input', { placeholder: t('familyCodePh'), maxlength: 8, class: 'ltr' });
    box.replaceChildren(
      h('form', { class: 'row-form', onsubmit: async e => { e.preventDefault(); await api('/api/citizen/family', { body: { name: name.value || 'My family' } }); PROFILE = null; loadFamily(); } }, name, h('button', { class: 'go small' }, t('familyCreate'))),
      h('form', { class: 'row-form', onsubmit: async e => { e.preventDefault(); try { await api('/api/citizen/family/join', { body: { code: code.value } }); PROFILE = null; loadFamily(); } catch (err) { banner('', err.message); } } }, code, h('button', { class: 'go small' }, t('familyJoin'))));
    return;
  }
  const msg = h('input', { placeholder: t('familySharePh'), maxlength: 300 });
  box.replaceChildren(h('p', {}, t('familyIn', fam.name, fam.members)), fam.code ? h('p', { class: 'hint' }, t('familyCode', fam.code)) : null,
    h('form', { class: 'row-form', onsubmit: async e => { e.preventDefault(); if (!msg.value.trim()) return; const r = await api('/api/citizen/family/share', { body: { title: msg.value.slice(0, 100), body: msg.value } }); msg.value = ''; banner('', t('familySent', r.sent_to)); } },
      msg, h('button', { class: 'go small' }, t('familyShare'))));
}

/* ---------------- report flow ---------------- */
const TYPES = ['auto', 'website', 'sms', 'whatsapp', 'phone', 'email', 'social', 'ad', 'qr', 'app', 'gov_bank', 'other'];
let rType = 'auto';
function renderTypes() {
  if (!META) return;
  $('#types').replaceChildren(...TYPES.map(k => h('button', { type: 'button', class: k === rType ? 'on' : '', 'aria-pressed': String(k === rType), onclick: () => selectType(k) },
    k === 'auto' ? t('auto') : typeLabel(k))));
}
function selectType(k) { rType = k; renderTypes(); }
$('#r-file').addEventListener('change', () => { $('#r-file-name').textContent = $('#r-file').files[0]?.name || ''; });
$$('.impact input').forEach(c => c.addEventListener('change', () => {
  $('#lost-help').hidden = !$$('.impact input').some(x => x.checked && (x.value === 'lost_money' || x.value === 'paid' || x.value === 'shared_details'));
}));
$('#report-form').addEventListener('submit', async e => {
  e.preventDefault();
  const text = $('#r-text').value.trim(), file = $('#r-file').files[0];
  if (!text && !file) { banner('', t('needInput')); return; }
  const fd = new FormData();
  fd.append('type', rType); fd.append('text', text); fd.append('emirate', $('#r-emirate').value);
  fd.append('impact', JSON.stringify(Object.fromEntries($$('.impact input').map(x => [x.value, x.checked]))));
  if (file) fd.append('file', file);
  const btn = $('#report-form .go'); btn.disabled = true; btn.textContent = t('sending');
  try {
    const r = await api('/api/citizen/report', { body: fd });
    showReportResult(r);
    $('#report-form').reset(); $('#r-file-name').textContent = ''; $('#lost-help').hidden = true; selectType('auto');
    loadMyReports();
  } catch (err) { banner('', err.message); }
  finally { btn.disabled = false; btn.textContent = t('submitReport'); }
});
function showReportResult(r) {
  const box = $('#r-result');
  box.hidden = false;
  box.replaceChildren(
    h('p', { class: 'ref' }, t('reportRef', r.ref)),
    h('p', {}, h('span', { class: `pill ${r.status}` }, statusLabel(r.status)), '  ', typeLabel(r.type)),
    r.risk != null ? h('p', { class: 'hint' }, t('riskLine', r.risk, sevLabel(r.severity))) : null,
    h('p', {}, r[`explanation_${lang}`]),
    r.duplicate_of ? h('p', { class: 'hint' }, t('duplicateNote', r.duplicate_of)) : h('p', { class: 'hint' }, t('nextSteps')));
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
const TRACK = ['under_review', 'community_corroborated', 'analyst_verified', 'confirmed_malicious'];
async function loadMyReports() {
  const ol = $('#my-reports');
  $('#anon-note').hidden = !!TOKEN;
  if (!TOKEN) { ol.replaceChildren(h('li', { class: 'hint' }, t('signInToTrack'))); return; }
  const rows = await api('/api/citizen/reports');
  ol.replaceChildren(...(rows.length ? rows.map(r => {
    const step = TRACK.indexOf(r.status);
    return h('li', {},
      h('div', { class: 'r-top' }, h('b', {}, r.ref), h('span', { class: `pill ${r.status}` }, statusLabel(r.status))),
      h('div', { class: 'hint' }, `${typeLabel(r.type)} · ${fmtDate(r.created)}`),
      r.links?.[0] ? h('div', { class: 'ltr small' }, r.links[0].url) : null,
      step >= 0 ? h('ol', { class: 'track', 'aria-label': t('status') }, TRACK.map((s, i) => h('li', { class: i <= step ? 'done' : '' }, statusLabel(s)))) : null);
  }) : [h('li', { class: 'hint' }, t('noReports'))]));
}

/* ---------------- community ---------------- */
let lbPeriod = 'week', SIMS = [], simIdx = 0;
$$('#lb-period button').forEach(b => b.addEventListener('click', () => { lbPeriod = b.dataset.p; $$('#lb-period button').forEach(x => x.classList.toggle('on', x === b)); loadBoard(); }));
$('#lb-emirate').addEventListener('change', () => loadBoard());
async function loadBoard() {
  const e = $('#lb-emirate').value;
  const d = await api(`/api/public/leaderboard?period=${lbPeriod}${e ? `&emirate=${encodeURIComponent(e)}` : ''}`);
  $('#leaderboard').replaceChildren(...(d.guardians.length ? d.guardians.map(g => h('li', {},
    h('span', { class: 'rk' }, g.rank), h('span', { class: 'nm' }, g.display_name, h('small', {}, `${g.level}${g.emirate ? ' · ' + emirateLabel(g.emirate) : ''}`)),
    h('span', { class: 'pt' }, t('pts', g.pts)))) : [h('li', { class: 'hint' }, t('noBoard'))]));
  $('#emirate-board').replaceChildren(...(d.emirates.length ? d.emirates.map(x => h('li', {}, h('span', { class: 'nm' }, emirateLabel(x.emirate)), h('span', { class: 'pt' }, t('pts', x.pts)))) : [h('li', { class: 'hint' }, t('noBoard'))]));
}
async function loadCommunity() {
  const [s, k] = await Promise.all([api('/api/public/safety-report'), api('/api/public/knowledge'), loadBoard()]);
  $('#safety').replaceChildren(h('dl', { class: 'stats' }, [[t('confirmedN'), s.confirmed_threats], [t('reportsN'), s.citizen_reports], [t('verifiedN'), s.verified_from_citizens]]
    .map(([a, b]) => h('div', {}, h('dt', {}, a), h('dd', {}, b)))),
    s.most_impersonated.length ? h('p', {}, h('b', {}, `${t('mostImp')}: `), s.most_impersonated.map(x => x.brand).join(lang === 'ar' ? '، ' : ', ')) : null,
    h('p', { class: 'hint' }, s.note));
  $('#knowledge').replaceChildren(...k.articles.map(a => h('details', {}, h('summary', {}, a[`title_${lang}`]), h('p', {}, a[`body_${lang}`]))));
  SIMS = k.simulations;
  renderSim();
}
function renderSim(result) {
  const box = $('#sim');
  if (simIdx >= SIMS.length) { box.replaceChildren(h('p', {}, t('simDone'))); return; }
  const s = SIMS[simIdx];
  const answer = async scam => renderSim({ ...(await api(`/api/learn/simulations/${s.id}`, { body: { scam } })) });
  box.replaceChildren(h('p', { class: 'hint' }, s.channel), h('blockquote', {}, s[`text_${lang}`]),
    result ? h('div', { class: `sim-res ${result.correct ? 'ok' : 'no'}` }, h('b', {}, result.correct ? t('right') : t('wrong'), result.points ? t('plusPts', result.points) : ''), h('p', {}, result[`why_${lang}`]),
      h('button', { class: 'soft', onclick: () => { simIdx++; renderSim(); } }, t('next')))
      : h('div', { class: 'two' }, h('button', { class: 'go small danger', onclick: () => answer(true) }, t('isScam')), h('button', { class: 'go small', onclick: () => answer(false) }, t('isSafe'))));
}

/* ---------------- profile ---------------- */
let authMode = 'register';
$$('#auth-mode button').forEach(b => b.addEventListener('click', () => { authMode = b.dataset.m; syncAuthForm(); }));
function syncAuthForm() {
  $$('#auth-mode button').forEach(x => x.classList.toggle('on', x.dataset.m === authMode));
  $('#reg-only').hidden = authMode !== 'register';
  $('#auth-submit').textContent = authMode === 'register' ? t('register') : t('signIn');
  $('#a-pass').autocomplete = authMode === 'register' ? 'new-password' : 'current-password';
}
$('#auth-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('#auth-error').textContent = '';
  try {
    const body = authMode === 'register'
      ? { email: $('#a-email').value, password: $('#a-pass').value, display_name: $('#a-name').value || null, emirate: $('#a-emirate').value, public_rank: $('#a-public').checked }
      : { email: $('#a-email').value, password: $('#a-pass').value };
    const r = await api(`/api/auth/${authMode === 'register' ? 'register' : 'login'}`, { body });
    if (r.user.role !== 'citizen') { $('#auth-error').textContent = 'Officials sign in to RAQEEB Command.'; return; }
    setToken(r.token); ME = r.user; PROFILE = null;
    $('#auth-form').reset();
    reconnect();
    loadProfile(); loadMyReports();
  } catch (err) { $('#auth-error').textContent = err.message; }
});
async function loadProfile() {
  $('#signed-out').hidden = !!TOKEN; $('#signed-in').hidden = !TOKEN;
  if (!TOKEN) return;
  const [p, notes] = await Promise.all([api('/api/citizen/profile'), api('/api/citizen/notifications')]);
  PROFILE = p; ME = p.user;
  const lv = p.level;
  $('#lvl-name').textContent = lang === 'ar' ? lv.name_ar : lv.name;
  $('#lvl-pts').textContent = `${p.user.display_name} · ${t('pts', p.points)}`;
  $('#lvl-bar').style.width = lv.next ? `${Math.min(100, 100 * (p.points - lv.threshold) / (lv.next.at - lv.threshold))}%` : '100%';
  $('#lvl-next').textContent = lv.next ? t('toNext', lv.next.name, lv.next.at, p.points) : t('topLevel');
  $('#badges').replaceChildren(...(p.badges.length ? p.badges.map(b => h('li', {}, h('b', {}, lang === 'ar' ? b.name_ar : b.name), h('small', {}, fmtDate(b.earned)))) : [h('li', { class: 'hint' }, t('noBadges'))]));
  $('#ledger').replaceChildren(...(p.ledger.length ? p.ledger.map(l => h('li', { class: 'row-item' }, h('span', {}, l.explanation, l.threat_id ? h('small', { class: 'ltr' }, ` ${l.threat_id}`) : null), h('b', { class: l.delta < 0 ? 'neg' : 'pos' }, (l.delta > 0 ? '+' : '') + l.delta))) : [h('li', { class: 'hint' }, t('noPoints'))]));
  $('#notes').replaceChildren(...(notes.length ? notes.map(n => h('li', {}, h('b', {}, n.title), h('div', { class: 'hint' }, `${n.body} · ${fmtDate(n.created)}`))) : [h('li', { class: 'hint' }, t('noNotes'))]));
  const seen = +localStorage.getItem('raqeeb_notes_seen') || 0;
  const fresh = notes.filter(n => n.created > seen).length;
  if ($('#t-profile').classList.contains('on')) localStorage.setItem('raqeeb_notes_seen', String(Date.now() / 1000));
  $('#note-count').hidden = !fresh || $('#t-profile').classList.contains('on'); $('#note-count').textContent = fresh;
  $('#s-name').value = p.user.display_name; $('#s-public').checked = !!p.user.public_rank;
  fillEmirates(); $('#s-emirate').value = p.user.emirate || 'Abu Dhabi';
}
$('#settings').addEventListener('submit', async e => {
  e.preventDefault();
  await api('/api/citizen/profile', { method: 'PATCH', body: { display_name: $('#s-name').value, emirate: $('#s-emirate').value, public_rank: $('#s-public').checked } });
  banner('', t('saved'), 2000); loadProfile();
});
$('#signout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* already signed out */ }
  setToken(null); ME = null; PROFILE = null; reconnect(); loadProfile(); loadMyReports();
});
$('#notify').addEventListener('click', async () => {
  if (!('Notification' in window)) return;
  if (await Notification.requestPermission() === 'granted') $('#notify').textContent = t('notifyOn');
});

/* ---------------- live updates ---------------- */
let ws = null;
function notifyDevice(title, body) {
  if ('Notification' in window && Notification.permission === 'granted') navigator.serviceWorker?.ready.then(reg => reg.showNotification(title, { body, icon: '/static/app/icon-192.png' }));
}
function connect() {
  const sock = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws${TOKEN ? `?token=${encodeURIComponent(TOKEN)}` : ''}`);
  sock.onclose = () => { if (sock === ws) setTimeout(connect, 2000); };
  sock.onmessage = ev => {
    const { event, data } = JSON.parse(ev.data);
    if (event === 'protection') {
      syncProtection(); loadAlerts();
      banner(t('newBlock'), t('newVersion', data.version));
      navigator.vibrate?.([200, 80, 200]);
      notifyDevice(t('newBlock'), t('newVersion', data.version));
    } else if (event === 'report_status') {
      banner(t('statusChanged', data.ref), statusLabel(data.status));
      notifyDevice(t('statusChanged', data.ref), statusLabel(data.status));
      loadMyReports(); loadProfile();
    }
  };
  ws = sock;
}
function reconnect() { const old = ws; ws = null; old?.close(); connect(); }

/* ---------------- start ---------------- */
const qs = new URLSearchParams(location.search);
const shared = [qs.get('title'), qs.get('text'), qs.get('url')].filter(Boolean).join(' ');
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
(async () => {
  try { META = await api('/api/public/meta'); } catch { /* offline: static text only */ }
  applyLang();
  syncProtection(); loadAlerts(); loadBrands().catch(() => {});
  connect();
  if (shared) { $('#input').value = shared; check(shared); }
})();
