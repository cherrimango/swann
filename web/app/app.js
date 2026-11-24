// RAQEEB PROTECT (installable web app). All text from the network is inserted with textContent, never as HTML.
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

const LANGS = ['en', 'ar', 'ur'];
let lang = LANGS.includes(localStorage.getItem('raqeeb-lang')) ? localStorage.getItem('raqeeb-lang') : 'en';
let TOKEN = localStorage.getItem('raqeeb_token');
let ME = null, META = null, PROFILE = null, DEMO = { enabled: false, accounts: [] };
const t = (k, ...a) => { const v = T[lang][k] ?? T.en[k]; return typeof v === 'function' ? v(...a) : v; };
const tr = (table, key, fallback) => table[lang]?.[key] || fallback || key;
const typeLabel = k => tr(TYPE_TR, k, META?.report_types[k]);
const statusLabel = s => tr(STATUS_TR, s, META?.statuses[s]);
const emirateLabel = e => tr(EMIRATE_TR, e, e);
const sevLabel = s => tr(SEVERITY_TR, s, s);
const loc = { en: 'en-GB', ar: 'ar-AE', ur: 'ur-PK' };
const fmtDate = ts => new Date(ts * 1000).toLocaleString(loc[lang], { dateStyle: 'medium', timeStyle: 'short' });
const pick = (obj, base) => obj?.[`${base}_${lang}`] || obj?.[`${base}_en`] || '';
const detail = e => (lang === 'ar' ? e.detail_ar : e.detail_en) || e.detail_en;
const levelName = lv => lang === 'ar' ? lv.name_ar : lang === 'ur' ? (LEVEL_UR[lv.name] || lv.name) : lv.name;

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  let body = opts.body;
  if (body && !(body instanceof FormData)) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(body); }
  const r = await fetch(path, { method: opts.method || (body ? 'POST' : 'GET'), headers, body });
  if (r.status === 401 && TOKEN) setToken(null);
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

/* ---------------- local activity (stays on this phone) ---------------- */
const store = {
  get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage full or blocked */ } },
};
function remember(kind, input, verdict) {
  const s = store.get('raqeeb_stats', { checks: 0, warned: 0 });
  s.checks++; if (['MALICIOUS', 'SUSPICIOUS', 'blocked', 'scam', 'suspicious', 'confirmed', 'verified'].includes(verdict)) s.warned++;
  store.set('raqeeb_stats', s);
  const r = store.get('raqeeb_recent', []);
  r.unshift({ kind, input: String(input).slice(0, 140), verdict, ts: Date.now() / 1000 });
  store.set('raqeeb_recent', r.slice(0, 20));
  renderRecent(); renderActivity();
}

/* ---------------- language ---------------- */
function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'en' ? 'ltr' : 'rtl';
  $$('[data-i]').forEach(el => { const v = t(el.dataset.i); if (typeof v === 'string') el.textContent = v; });
  $$('[data-ph]').forEach(el => { el.placeholder = t(el.dataset.ph); });
  $$('.langs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
  fillEmirates(); renderTypes(); renderShield(); renderAlerts(); renderRecent(); renderActivity(); renderCheckerTabs(); renderChecker();
  if (BRANDS) renderBrands();
  syncAuthForm(); renderSuggest(); renderQuickKinds(); renderHello();
  for (const fn of [loadSeason, loadMyReports, loadBlocks, loadFamily, loadCommunity, loadProfile, loadEmergency]) fn().catch(() => {});
}
$$('.langs button').forEach(b => b.addEventListener('click', () => { lang = b.dataset.lang; localStorage.setItem('raqeeb-lang', lang); applyLang(); }));

/* ---------------- tabs and sheets ---------------- */
function go(tab, scrollId) {
  $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === tab));
  $$('.tab').forEach(x => x.classList.toggle('on', x.id === `t-${tab}`));
  scrollTo(0, 0);
  ({ protect: () => { loadBlocks(); loadFamily(); }, report: loadMyReports, community: loadCommunity, profile: loadProfile }[tab])?.();
  if (scrollId) setTimeout(() => document.getElementById(scrollId)?.scrollIntoView({ behavior: 'smooth' }), 60);
}
$$('.tabs button').forEach(b => b.addEventListener('click', () => go(b.dataset.tab)));
document.addEventListener('click', e => {
  const g = e.target.closest('[data-goto]');
  if (g) { closeSheets(); go(g.dataset.goto, g.dataset.scroll); }
  const o = e.target.closest('[data-open]');
  if (o) openSheet(o.dataset.open);
  if (e.target.closest('[data-close]') && !g) closeSheets();
});
function openSheet(id) { closeSheets(); $(`#${id}`).hidden = false; document.body.classList.add('locked'); $(`#${id} textarea, #${id} input`)?.focus(); }
function closeSheets() { $$('.panel-sheet').forEach(s => { s.hidden = true; }); document.body.classList.remove('locked'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeSheets(); $('#verdict').hidden = true; } });

function fillEmirates() {
  if (!META) return;
  for (const id of ['#r-emirate', '#a-emirate', '#s-emirate']) {
    const sel = $(id), cur = sel.value || ME?.emirate || 'Abu Dhabi';
    sel.replaceChildren(...META.emirates.map(e => h('option', { value: e, selected: e === cur }, emirateLabel(e))));
  }
  const lb = $('#lb-emirate'), cur = lb.value;
  lb.replaceChildren(h('option', { value: '' }, t('allEmirates')), ...META.emirates.map(e => h('option', { value: e, selected: e === cur }, emirateLabel(e))));
}
function renderHello() {
  $('#hello-name').textContent = ME ? t('hello', ME.display_name) : t('helloGuest');
}

/* ---------------- signed protection package (works offline) ---------------- */
let PKG = store.get('raqeeb_pkg', null);
let SIG_STATE = localStorage.getItem('raqeeb_sig') || 'sigServer';
let ONLINE = true;
async function verifyPackage(pkg) {
  try {
    const { public_key } = await api('/api/protection/public-key');
    const raw = Uint8Array.from(atob(public_key), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    const sig = Uint8Array.from(atob(pkg.signature), c => c.charCodeAt(0));
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, new TextEncoder().encode(pkg.signed_payload)) ? 'sigOk' : 'sigBad';
  } catch { return 'sigServer'; }  // no Ed25519 in this browser's WebCrypto, or no secure context
}
async function syncProtection() {
  try {
    const pkg = await api('/api/protection/latest');
    ONLINE = true;
    if (PKG && pkg.payload.version === PKG.payload.version) { renderShield(); return; }
    const state = await verifyPackage(pkg);
    if (state === 'sigBad') { SIG_STATE = 'sigBad'; renderShield(); return; }
    PKG = pkg; SIG_STATE = state;
    store.set('raqeeb_pkg', pkg); localStorage.setItem('raqeeb_sig', state);
  } catch { ONLINE = false; }
  renderShield();
}
const activeRules = () => (PKG?.payload.rules || []).filter(r => !r.expires || r.expires > Date.now() / 1000);
function renderShield() {
  $('#shield').classList.toggle('offline', !ONLINE);
  $('#shield-state').textContent = ONLINE ? t('shieldOn') : t('shieldOffline');
  $('#shield-meta').textContent = PKG ? t('shieldMeta', PKG.payload.version, activeRules().length, t(SIG_STATE)) : '';
}
function hostOf(s) {
  try { return new URL(/^[a-z]+:\/\//i.test(s) ? s : 'http://' + s).hostname.replace(/^www\./, '').toLowerCase(); } catch { return ''; }
}
function localRule(input) {
  const s = input.trim(), host = hostOf(s);
  let path = '';
  try { const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : 'http://' + s); path = host + u.pathname.replace(/\/$/, '') + u.search; } catch { /* not a URL */ }
  const digits = s.replace(/[^\d]/g, '');
  return activeRules().find(r => (r.type === 'url' && path.startsWith(r.value)) ||
    ((r.type === 'domain' || r.type === 'host') && host && (host === r.value || host.endsWith('.' + r.value))) ||
    (r.type === 'phone' && digits.length > 7 && r.value.replace(/[^\d]/g, '').endsWith(digits.slice(-9))));
}

/* ---------------- home check + verdict sheet ---------------- */
const looksLikeLink = s => !/\s/.test(s.trim()) && /[.]/.test(s);
let lastInput = '', lastResult = null;
$('#check-form').addEventListener('submit', e => { e.preventDefault(); check($('#input').value); });
async function scanLink(url) {
  const r = await api('/api/v1/scan', { body: { url, mode: 'quick' } });
  const blocked = r.signature_result?.matches?.some(m => m.source === 'raqeeb_published') || !!localRule(url);
  return { kind: 'link', verdict: blocked ? 'blocked' : r.verdict, report: r, twin: r.twin_view, brand: r.detected_brand,
           host: hostOf(url), reasons: r.strongest_indicators.map(detail), confidence: r.assessment_confidence };
}
async function check(raw) {
  const text = (raw || '').trim();
  if (!text) { banner('', t('empty'), 3000); return; }
  lastInput = text;
  const btn = $('#check-form .go'); btn.textContent = t('checking'); btn.disabled = true;
  try {
    let r;
    if (looksLikeLink(text)) r = await scanLink(text);
    else {
      const m = await api('/api/check-message', { body: { text } });
      const worst = [...m.links].sort((a, b) => b.risk_score - a.risk_score)[0];
      const v = m.links.some(l => l.blocked) || localRule(text) ? 'blocked' : m.verdict === 'scam' ? 'MALICIOUS' : m.verdict === 'suspicious' ? 'SUSPICIOUS' : 'SAFE';
      r = { kind: 'message', verdict: v, msg: m, twin: worst?.impersonated_brand?.twin, brand: worst?.impersonated_brand?.name,
            brand_ar: worst?.impersonated_brand?.name_ar, host: worst?.host,
            reasons: [...m.script_signals.map(s => s[lang === 'ar' ? 'ar' : 'en']), ...(worst ? worst.reasons.map(x => x[lang === 'ar' ? 'ar' : 'en']) : [])] };
    }
    lastResult = r; remember(r.kind, text, r.verdict); showVerdict(r);
  } catch {
    ONLINE = false; renderShield();
    if (localRule(text)) showVerdict({ verdict: 'blocked', reasons: [] }); else banner('', t('offline'));
  } finally { btn.textContent = t('checkBtn'); btn.disabled = false; }
}
const TONE = { blocked: 'scam', MALICIOUS: 'scam', SUSPICIOUS: 'suspicious', INCONCLUSIVE: 'unclear', SAFE: 'safe' };
function seg(segs) { return h('span', { class: 'host' }, segs.map(s => s.type === 'same' ? s.text : h('span', { class: s.type }, s.text))); }
function showVerdict(r) {
  const sheet = $('#verdict'), tone = TONE[r.verdict] || 'unclear';
  sheet.className = `sheet ${tone}`;
  $('#v-word').textContent = r.verdict === 'blocked' ? t('blocked') : t(r.verdict);
  $('#v-brand').textContent = r.brand && tone !== 'safe' ? t('pretends', lang === 'ar' && r.brand_ar ? r.brand_ar : r.brand) : '';
  const twin = $('#v-twin'); twin.replaceChildren();
  if (r.twin && tone !== 'safe') {
    twin.append(h('div', { class: 'row' }, h('span', { class: 'lbl' }, t('thisLink')), seg(r.twin.scam_segments)),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, t('official')), seg(r.twin.official_segments)),
      h('p', { class: 'note' }, r.twin.unicode_tricks.length ? t('unicodeNote', r.twin.unicode_tricks[0]) : t('similar', Math.round(r.twin.similarity * 100))));
  }
  const seen = new Set();
  const reasons = (r.verdict === 'blocked' ? [t('blockedRule')] : []).concat((r.reasons || []).filter(x => x && !seen.has(x) && seen.add(x)).slice(0, 4));
  $('#v-reasons').replaceChildren(...reasons.map(x => h('li', {}, x)));
  $('#v-advice').textContent = ({ scam: t('adviceScam'), suspicious: t('adviceWarn'), safe: t('adviceSafe'), unclear: t('adviceUnclear') })[tone] +
    (r.confidence ? ` ${t('confidence', r.confidence)}.` : '');
  $('#v-block').textContent = t('blockForMe'); $('#v-block').disabled = false;
  sheet.hidden = false; sheet.scrollTop = 0;
  if (tone === 'scam') navigator.vibrate?.([120, 60, 120]);
}
$('#v-close').addEventListener('click', () => { $('#verdict').hidden = true; });
$('#v-report').addEventListener('click', () => {
  $('#verdict').hidden = true;
  $('#r-text').value = lastInput;
  selectType(lastResult?.kind === 'link' ? 'website' : 'auto');
  go('report'); $('#r-text').focus();
});
$('#v-block').addEventListener('click', async () => {
  if (!TOKEN) { banner('', t('signInFirst')); return; }
  try { await api('/api/citizen/blocks', { body: { value: lastResult?.host || lastInput } }); $('#v-block').textContent = t('blockedForMe'); $('#v-block').disabled = true; renderActivity(); }
  catch (e) { banner('', e.message); }
});

/* QR codes (fake parking and payment stickers): read the code, then check where it leads before opening */
let stream = null;
async function scanQr(onCode) {
  if (!('BarcodeDetector' in window)) { banner('', t('noQr')); return; }
  const det = new BarcodeDetector({ formats: ['qr_code'] });
  try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } }); } catch { banner('', t('noQr')); return; }
  const v = $('#qr-video'); v.srcObject = stream; await v.play(); $('#qr-box').hidden = false;
  if ($('#t-protect').classList.contains('on')) go('home');
  const tick = async () => {
    if (!stream) return;
    const codes = await det.detect(v).catch(() => []);
    if (codes.length) { stopQr(); banner('', t('qrFound'), 2500); onCode(codes[0].rawValue); return; }
    requestAnimationFrame(tick);
  };
  tick();
}
function stopQr() { stream?.getTracks().forEach(x => x.stop()); stream = null; $('#qr-box').hidden = true; }
$('#qr-btn').addEventListener('click', () => scanQr(code => { $('#input').value = code; check(code); }));
$('#qr-stop').addEventListener('click', stopQr);

/* ---------------- home widgets ---------------- */
let ALERTS = [];
async function loadAlerts() { try { ALERTS = await api('/api/public/alerts'); } catch { ALERTS = []; } renderAlerts(); }
function alertItem(a) {
  return h('li', {}, h('b', { class: 'ltr' }, a.normalized),
    h('span', {}, [a.brand ? t('pretends', a.brand) : '', lang === 'en' && META ? META.categories[a.category] : ''].filter(Boolean).join(' · ')),
    h('div', { class: 'when' }, fmtDate(a.last_seen)));
}
function renderAlerts() {
  const empty = () => h('li', { class: 'empty' }, t('noAlerts'));
  $('#alerts').replaceChildren(...(ALERTS.length ? ALERTS.slice(0, 3).map(alertItem) : [empty()]));
  $('#alerts-full').replaceChildren(...(ALERTS.length ? ALERTS.map(alertItem) : [empty()]));
}
async function loadSeason() {
  const f = await api('/api/public/forecast');
  const items = f.predicted.filter(p => p.basis === 'seasonal pattern').slice(0, 3);
  $('#season-card').hidden = !items.length;
  $('#season-list').replaceChildren(...items.map(p => h('li', {}, h('b', {}, lang === 'ar' ? p.season_ar || p.season : p.season), p.advice && lang === 'en' ? h('div', { class: 'hint' }, p.advice) : null)));
}
function renderActivity() {
  const s = store.get('raqeeb_stats', { checks: 0, warned: 0 });
  $('#my-activity').replaceChildren(...[[t('actChecks'), s.checks], [t('actWarned'), s.warned], [t('actBlocks'), PROFILE ? (BLOCKS?.length ?? 0) : '–']]
    .map(([a, b]) => h('div', {}, h('dt', {}, a), h('dd', {}, b))));
  const g = $('#guardian-mini');
  g.hidden = !PROFILE;
  if (PROFILE) {
    const lv = PROFILE.level;
    g.replaceChildren(h('b', {}, t('actLevel', levelName(lv), PROFILE.points)),
      h('div', { class: 'meter' }, h('i', { style: `width:${lv.next ? Math.min(100, 100 * (PROFILE.points - lv.threshold) / (lv.next.at - lv.threshold)) : 100}%` })));
  }
}

/* ---------------- Protect: checkers ---------------- */
const CHECKERS = ['website', 'payment', 'qr', 'message', 'phone', 'ad', 'app'];
const CK_KEYS = { website: 'Website', payment: 'Payment', qr: 'Qr', message: 'Message', phone: 'Phone', ad: 'Ad', app: 'App' };
let ckType = 'website';
function renderCheckerTabs() {
  $('#checker-tabs').replaceChildren(...CHECKERS.map(k => h('button', { role: 'tab', 'aria-selected': String(k === ckType), class: k === ckType ? 'on' : '',
    onclick: () => { ckType = k; renderCheckerTabs(); renderChecker(); } }, t(`ck${CK_KEYS[k]}`))));
}
function renderChecker() {
  const k = CK_KEYS[ckType], box = $('#checker');
  const multi = ['message', 'ad'].includes(ckType);
  const input = multi ? h('textarea', { id: 'ck-in', rows: 4, placeholder: t(`ph${k}`) }) : h('input', { id: 'ck-in', placeholder: t(`ph${k}`), inputmode: ckType === 'phone' ? 'tel' : 'url' });
  const out = h('div', { id: 'ck-out', class: 'ck-out', 'aria-live': 'polite' });
  const file = ckType === 'ad' ? h('label', { class: 'file' }, h('span', {}, t('attachAd')), h('input', { id: 'ck-file', type: 'file', accept: 'image/png,image/jpeg,image/webp' })) : null;
  const deep = ['website', 'payment', 'qr'].includes(ckType) ? h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'ck-deep' }), h('span', {}, t('deep'))) : null;
  const scan = ckType === 'qr' ? h('button', { type: 'button', class: 'soft', onclick: () => scanQr(code => { go('protect'); $('#ck-in').value = code; runChecker(); }) }, t('qrBtn')) : null;
  box.replaceChildren(h('p', { class: 'hint' }, t(`ck${k}L`)),
    h('form', { class: 'stack', onsubmit: e => { e.preventDefault(); runChecker(); } }, input, file, deep, h('div', { class: 'two' }, h('button', { class: 'go', type: 'submit' }, t('run')), scan)), out);
}
function resultCard(tone, title, lines, extra) {
  return h('div', { class: `res ${tone}` }, h('p', { class: 'res-word' }, title), h('ul', {}, lines.filter(Boolean).map(l => h('li', {}, l))), extra || null);
}
async function runChecker() {
  const val = $('#ck-in').value.trim(), out = $('#ck-out');
  if (!val && !$('#ck-file')?.files[0]) { banner('', t('empty'), 2500); return; }
  out.replaceChildren(h('p', { class: 'hint' }, t('checking')));
  try {
    if (['website', 'payment', 'qr'].includes(ckType)) {
      const deep = $('#ck-deep')?.checked && TOKEN;
      let r = await api('/api/v1/scan', { body: { url: val, mode: deep ? 'deep' : 'quick' } });
      while (r.status === 'running') { await new Promise(res => setTimeout(res, 1500)); r = await api(`/api/v1/scan/${r.scan_id}`); }
      const blocked = r.signature_result?.matches?.some(m => m.source === 'raqeeb_published');
      const v = blocked ? 'blocked' : r.verdict, tone = TONE[v];
      lastInput = val; lastResult = { kind: 'link', host: hostOf(val) };
      remember(ckType, val, v);
      const lines = [r.detected_brand && tone !== 'safe' ? t('pretends', r.detected_brand) : null, ...r.strongest_indicators.map(detail),
        t('confidence', r.assessment_confidence), t('completeness', Math.round(r.analysis_completeness * 100)),
        r.final_url && r.final_url !== r.normalised_url ? `${t('goesTo')}: ${r.final_url}` : null, ckType === 'payment' ? t('payWarn') : null];
      out.replaceChildren(resultCard(tone, v === 'blocked' ? t('blocked') : t(v), lines,
        h('div', { class: 'two' }, h('button', { class: 'soft', onclick: () => { $('#r-text').value = val; selectType(ckType === 'qr' ? 'qr' : 'website'); go('report'); } }, t('reportToRaqeeb')),
          h('button', { class: 'soft', onclick: () => preview(val, out) }, t('preview')))));
    } else if (ckType === 'message') {
      const m = await api('/api/check-message', { body: { text: val } });
      const v = m.links.some(l => l.blocked) ? 'blocked' : m.verdict === 'scam' ? 'MALICIOUS' : m.verdict === 'suspicious' ? 'SUSPICIOUS' : 'SAFE';
      remember('message', val, v);
      out.replaceChildren(resultCard(TONE[v], v === 'blocked' ? t('blocked') : t(v),
        [...m.script_signals.map(s => s[lang === 'ar' ? 'ar' : 'en']), ...m.links.map(l => `${l.host}: ${t(l.verdict === 'phishing' ? 'MALICIOUS' : l.verdict === 'suspicious' ? 'SUSPICIOUS' : 'SAFE')}`), m[`advice_${lang === 'ar' ? 'ar' : 'en'}`]]));
    } else if (ckType === 'phone') {
      const p = await api(`/api/public/check-phone?number=${encodeURIComponent(val)}`);
      remember('phone', p.number, p.verdict);
      const pv = T[lang].phoneVerdict || T.en.phoneVerdict;
      const title = p.verdict === 'reported' ? pv.reported(p.reports) : pv[p.verdict];
      out.replaceChildren(resultCard(['blocked', 'confirmed'].includes(p.verdict) ? 'scam' : p.verdict === 'unknown' ? 'unclear' : 'suspicious', title,
        [p.number, ...p.signals, p.personal_block ? t('blockedForMe') : null, p.note]));
    } else if (ckType === 'ad') {
      const fd = new FormData(); fd.append('text', val);
      const f = $('#ck-file')?.files[0]; if (f) fd.append('file', f);
      const a = await api('/api/public/check-ad', { body: fd });
      remember('ad', val || f.name, a.verdict);
      const av = T[lang].adVerdict || T.en.adVerdict;
      out.replaceChildren(resultCard(a.verdict === 'scam' ? 'scam' : a.verdict === 'suspicious' ? 'suspicious' : 'unclear', av[a.verdict],
        [...a.signals.map(s => s.en), ...a.script_signals.map(s => s[lang === 'ar' ? 'ar' : 'en']), ...a.links.map(l => `${l.url}: ${Math.round(l.risk)}/100`),
          a.phones.length ? a.phones.join(', ') : null, f ? t('ocrNote', a.ocr) : null],
        h('button', { class: 'soft', onclick: () => { $('#r-text').value = val || a.extracted_text; selectType('ad'); go('report'); } }, t('reportToRaqeeb'))));
    } else if (ckType === 'app') {
      const host = hostOf(val);
      const store = { 'play.google.com': 'Google Play', 'apps.apple.com': 'the App Store', 'appgallery.huawei.com': 'Huawei AppGallery' }[host];
      const apk = /\.apk(\?|$)/i.test(val);
      let lines = [store ? t('appStore', store) : apk ? t('appApk') : t('appOther'), t('appNote')];
      let tone = store ? 'unclear' : 'scam';
      if (!store && looksLikeLink(val)) {
        const r = await scanLink(val);
        lines = [...lines, ...r.reasons];
        tone = apk ? 'scam' : TONE[r.verdict];
      }
      remember('app', val, store ? 'INCONCLUSIVE' : 'SUSPICIOUS');
      out.replaceChildren(resultCard(tone, store ? t('INCONCLUSIVE') : t(apk ? 'MALICIOUS' : 'SUSPICIOUS'), lines));
    }
  } catch (err) { out.replaceChildren(h('p', { class: 'error' }, err.message)); }
}
async function preview(url, out) {
  try {
    const p = await api(`/api/preview?url=${encodeURIComponent(url)}`);
    out.append(h('div', { class: 'card inset' }, p.final_url ? h('p', {}, h('b', {}, `${t('goesTo')}: `), h('span', { class: 'ltr' }, p.final_url)) : null,
      p.chain ? h('p', { class: 'hint' }, t('hops', Math.max(0, p.chain.length - 1))) : null, p.title ? h('p', {}, h('b', {}, `${t('pageTitle')}: `), p.title) : null,
      p.error ? h('p', { class: 'hint' }, p.error) : null));
  } catch (err) { banner('', err.message); }
}
function renderRecent() {
  const r = store.get('raqeeb_recent', []);
  $('#recent').replaceChildren(...(r.length ? r.slice(0, 8).map(x => h('li', { class: `tone-${TONE[x.verdict] || (['scam', 'confirmed', 'blocked'].includes(x.verdict) ? 'scam' : x.verdict === 'suspicious' || x.verdict === 'reported' || x.verdict === 'verified' ? 'suspicious' : 'unclear')}` },
    h('span', { class: 'ltr r-in' }, x.input), h('span', { class: 'hint' }, `${t(`ck${CK_KEYS[x.kind === 'link' ? 'website' : x.kind] || 'Website'}`)} · ${fmtDate(x.ts)}`)))
    : [h('li', { class: 'hint empty' }, t('noRecent'))]));
}
$('#clear-recent').addEventListener('click', () => { store.set('raqeeb_recent', []); renderRecent(); });

let BLOCKS = null;
async function loadBlocks() {
  const ul = $('#myblocks');
  if (!TOKEN) { ul.replaceChildren(h('li', { class: 'hint' }, t('signInFirst'))); return; }
  BLOCKS = await api('/api/citizen/blocks');
  renderActivity();
  ul.replaceChildren(...(BLOCKS.length ? BLOCKS.map(b => h('li', { class: 'row-item' }, h('span', { class: 'ltr' }, b.value),
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
  const list = BRANDS.filter(b => !q || (b.name + ' ' + b.name_ar + ' ' + b.official_domains.map(d => d.domain).join(' ')).toLowerCase().includes(q)).slice(0, q ? 12 : 5);
  $('#brands').replaceChildren(...list.map(b => h('li', {}, h('b', {}, lang === 'ar' ? b.name_ar : b.name),
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
  $('#types').replaceChildren(...TYPES.map(k => h('button', { type: 'button', class: k === rType ? 'on' : '', 'aria-pressed': String(k === rType), onclick: () => selectType(k) }, k === 'auto' ? t('auto') : typeLabel(k))));
}
function selectType(k) { rType = k; renderTypes(); }
$('#r-file').addEventListener('change', () => { $('#r-file-name').textContent = $('#r-file').files[0]?.name || ''; });
$$('.impact input').forEach(c => c.addEventListener('change', () => {
  $('#lost-help').hidden = !$$('.impact input').some(x => x.checked && ['lost_money', 'paid', 'shared_details'].includes(x.value));
}));
async function sendReport(type, text, file, impact, emirate) {
  const fd = new FormData();
  fd.append('type', type); fd.append('text', text); fd.append('emirate', emirate || $('#r-emirate').value);
  fd.append('impact', JSON.stringify(impact || {}));
  if (file) fd.append('file', file);
  return api('/api/citizen/report', { body: fd });
}
$('#report-form').addEventListener('submit', async e => {
  e.preventDefault();
  const text = $('#r-text').value.trim(), file = $('#r-file').files[0];
  if (!text && !file) { banner('', t('needInput')); return; }
  const btn = $('#report-form .go'); btn.disabled = true; btn.textContent = t('sending');
  $('#r-result').hidden = false; $('#r-result').replaceChildren(h('p', { class: 'ref' }, t('thanks')));
  try {
    const r = await sendReport(rType, text, file, Object.fromEntries($$('.impact input').map(x => [x.value, x.checked])));
    showReportResult(r, $('#r-result'));
    $('#report-form').reset(); $('#r-file-name').textContent = ''; $('#lost-help').hidden = true; selectType('auto');
    loadMyReports();
  } catch (err) { $('#r-result').hidden = true; banner('', err.message); }
  finally { btn.disabled = false; btn.textContent = t('submitReport'); }
});
function showReportResult(r, box) {
  box.hidden = false;
  box.replaceChildren(h('p', { class: 'thanks' }, t('thanks')), h('p', { class: 'ref' }, t('reportRef', r.ref)),
    h('p', {}, h('span', { class: `pill ${r.status}` }, statusLabel(r.status)), '  ', typeLabel(r.type)),
    r.risk != null ? h('p', { class: 'hint' }, t('riskLine', r.risk, sevLabel(r.severity))) : null,
    h('p', {}, lang === 'ar' ? r.explanation_ar : r.explanation_en),
    h('p', { class: 'hint' }, r.duplicate_of ? t('duplicateNote', r.duplicate_of) : t('nextSteps')));
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
    const more = h('form', { class: 'row-form details', hidden: true, onsubmit: async e => {
      e.preventDefault(); const inp = e.target.querySelector('input'); if (!inp.value.trim()) return;
      await api(`/api/citizen/reports/${r.ref}/details`, { body: { text: inp.value } }); inp.value = ''; e.target.hidden = true; banner('', t('detailsSaved'), 2500);
    } }, h('input', { placeholder: t('addDetailsPh'), maxlength: 2000 }), h('button', { class: 'go small' }, t('saveDetails')));
    return h('li', {},
      h('div', { class: 'r-top' }, h('b', { class: 'ltr' }, r.ref), h('span', { class: `pill ${r.status}` }, statusLabel(r.status))),
      h('div', { class: 'hint' }, `${typeLabel(r.type)} · ${fmtDate(r.created)}`),
      r.links?.[0] ? h('div', { class: 'ltr small' }, r.links[0].url) : null,
      step >= 0 ? h('ol', { class: 'track', 'aria-label': t('status') }, TRACK.map((s, i) => h('li', { class: i <= step ? 'done' : '' }, statusLabel(s)))) : null,
      h('button', { class: 'link', onclick: () => { more.hidden = !more.hidden; } }, t('addDetails')), more);
  }) : [h('li', { class: 'hint' }, t('noReports'))]));
}

/* ---------------- quick alert (scam call) ---------------- */
function renderQuickKinds() {
  const k = T[lang].qaKinds || T.en.qaKinds, sel = $('#qa-kind'), cur = sel.value;
  sel.replaceChildren(...Object.entries(k).map(([v, l]) => h('option', { value: v, selected: v === cur }, l)));
}
$('#open-quick').addEventListener('click', () => { $('#qa-done').hidden = true; $('#quick-form').hidden = false; openSheet('quick'); });
$('#quick-form').addEventListener('submit', async e => {
  e.preventDefault();
  const num = $('#qa-number').value.trim(), kind = $('#qa-kind').value, what = $('#qa-text').value.trim();
  const text = [num, `Quick Alert: suspicious call. Caller claimed to be: ${T.en.qaKinds[kind]}.`, what].filter(Boolean).join('\n');
  try {
    const r = await sendReport(num ? 'phone' : 'other', text, null, {}, ME?.emirate);
    $('#quick-form').reset(); $('#quick-form').hidden = true;
    const box = $('#qa-done'); box.hidden = false;
    box.replaceChildren(h('p', { class: 'thanks' }, t('thanks')), h('p', {}, t('qaDone', r.ref)), h('button', { class: 'soft', 'data-goto': 'report', 'data-close': '' }, t('myReports')));
    loadMyReports();
  } catch (err) { banner('', err.message); }
});

/* ---------------- assistant ---------------- */
function renderSuggest() {
  $('#suggest').replaceChildren(...(T[lang].suggestions || T.en.suggestions).map(s => h('button', { type: 'button', onclick: () => ask(s) }, s)));
}
function bubble(who, ...kids) { const li = h('li', { class: `msg ${who}` }, ...kids); $('#chat').append(li); li.scrollIntoView({ block: 'end' }); return li; }
$('#open-assistant').addEventListener('click', () => {
  if (!$('#chat').children.length) bubble('bot', h('p', {}, t('asHello')));
  openSheet('assistant');
});
$('#ask-form').addEventListener('submit', e => { e.preventDefault(); ask($('#ask').value); });
async function ask(text) {
  text = (text || '').trim();
  if (!text) return;
  $('#ask').value = '';
  bubble('me', h('p', { dir: 'auto' }, text));
  const wait = bubble('bot', h('p', { class: 'hint' }, t('asThinking')));
  try {
    const a = await api('/api/assistant', { body: { message: text } });
    const sections = [];
    if (a.live_intelligence.length) sections.push(h('div', { class: 'live' }, h('span', { class: 'tag' }, a.labels.live), h('ul', {}, a.live_intelligence.map(x => h('li', { dir: 'auto' }, x)))));
    sections.push(h('div', {}, h('span', { class: 'tag soft-tag' }, a.labels.general),
      a.answer_source.startsWith('llm') ? h('p', { dir: 'auto' }, a.answer) : h('ul', {}, a.guidance.map(x => h('li', { dir: 'auto' }, x)))));
    if (a.urgent) sections.push(h('button', { class: 'go small danger', onclick: () => openSheet('emergency') }, t('qHelp')));
    sections.push(h('p', { class: 'disclaimer', dir: 'auto' }, a.disclaimer));
    wait.replaceChildren(...sections);
    if (a.tools.some(x => x.tool === 'link_intelligence_engine')) remember('link', a.tools.find(x => x.tool === 'link_intelligence_engine').input, a.tools.find(x => x.tool === 'link_intelligence_engine').verdict);
  } catch (err) { wait.replaceChildren(h('p', { class: 'error' }, err.message)); }
}

/* ---------------- emergency guidance ---------------- */
let EMERGENCY = null;
async function loadEmergency() {
  EMERGENCY = EMERGENCY || await api('/api/public/emergency');
  $('#em-steps').replaceChildren(...(EMERGENCY[lang] || EMERGENCY.en).map(s => h('li', {}, s)));
}
$('#open-emergency').addEventListener('click', () => { loadEmergency().catch(() => {}); openSheet('emergency'); });

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
    s.most_impersonated.length ? h('p', {}, h('b', {}, `${t('mostImp')}: `), s.most_impersonated.map(x => x.brand).join(lang === 'en' ? ', ' : '، ')) : null,
    h('p', { class: 'hint' }, s.note));
  $('#knowledge').replaceChildren(...k.articles.map(a => h('details', {}, h('summary', {}, pick(a, 'title')), h('p', {}, pick(a, 'body')))));
  SIMS = k.simulations;
  renderSim();
}
function renderSim(result) {
  const box = $('#sim');
  if (simIdx >= SIMS.length) { box.replaceChildren(h('p', {}, t('simDone'))); return; }
  const s = SIMS[simIdx];
  const answer = async scam => renderSim(await api(`/api/learn/simulations/${s.id}`, { body: { scam } }));
  box.replaceChildren(h('p', { class: 'hint' }, s.channel), h('blockquote', { dir: 'auto' }, pick(s, 'text')),
    result ? h('div', { class: `sim-res ${result.correct ? 'ok' : 'no'}` }, h('b', {}, result.correct ? t('right') : t('wrong'), result.points ? t('plusPts', result.points) : ''), h('p', {}, pick(result, 'why')),
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
async function signIn(body, register) {
  const r = await api(`/api/auth/${register ? 'register' : 'login'}`, { body });
  if (r.user.role !== 'citizen') throw new Error('Officials sign in to RAQEEB COMMAND.');
  setToken(r.token); ME = r.user; PROFILE = null;
  reconnect(); loadProfile(); loadMyReports(); renderHello();
}
$('#auth-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('#auth-error').textContent = '';
  try {
    const reg = authMode === 'register';
    await signIn(reg ? { email: $('#a-email').value, password: $('#a-pass').value, display_name: $('#a-name').value || null, emirate: $('#a-emirate').value, public_rank: $('#a-public').checked }
      : { email: $('#a-email').value, password: $('#a-pass').value }, reg);
    $('#auth-form').reset();
  } catch (err) { $('#auth-error').textContent = err.message; }
});
function renderDemoCitizen() {
  const acct = DEMO.accounts.find(a => a.app === 'protect');
  const box = $('#demo-citizen');
  box.hidden = !acct;
  if (acct) box.replaceChildren(h('button', { class: 'soft', onclick: () => signIn({ email: acct.email, password: acct.password }).catch(err => banner('', err.message)) }, t('demoCitizen')),
    h('p', { class: 'hint' }, `${acct.email} · ${t('demoNote')}`));
}
async function loadProfile() {
  $('#signed-out').hidden = !!TOKEN; $('#signed-in').hidden = !TOKEN;
  if (!TOKEN) { PROFILE = null; renderActivity(); return; }
  const [p, notes] = await Promise.all([api('/api/citizen/profile'), api('/api/citizen/notifications')]);
  PROFILE = p; ME = p.user;
  renderHello(); renderActivity();
  const lv = p.level;
  $('#lvl-name').textContent = levelName(lv);
  $('#lvl-pts').textContent = `${p.user.display_name} · ${t('pts', p.points)}`;
  $('#lvl-bar').style.width = lv.next ? `${Math.min(100, 100 * (p.points - lv.threshold) / (lv.next.at - lv.threshold))}%` : '100%';
  $('#lvl-next').textContent = lv.next ? t('toNext', lv.next.name, lv.next.at, p.points) : t('topLevel');
  $('#badges').replaceChildren(...(p.badges.length ? p.badges.map(b => h('li', {}, h('b', {}, lang === 'ar' ? b.name_ar : b.name), h('small', {}, fmtDate(b.earned)))) : [h('li', { class: 'hint' }, t('noBadges'))]));
  $('#ledger').replaceChildren(...(p.ledger.length ? p.ledger.map(l => h('li', { class: 'row-item' }, h('span', {}, l.explanation, l.threat_id ? h('small', { class: 'ltr' }, ` ${l.threat_id}`) : null), h('b', { class: l.delta < 0 ? 'neg' : 'pos' }, (l.delta > 0 ? '+' : '') + l.delta))) : [h('li', { class: 'hint' }, t('noPoints'))]));
  $('#notes').replaceChildren(...(notes.length ? notes.map(n => h('li', {}, h('b', {}, n.title), h('div', { class: 'hint' }, `${n.body} · ${fmtDate(n.created)}`))) : [h('li', { class: 'hint' }, t('noNotes'))]));
  const seen = +localStorage.getItem('raqeeb_notes_seen') || 0;
  const onProfile = $('#t-profile').classList.contains('on');
  const fresh = notes.filter(n => n.created > seen).length;
  if (onProfile) localStorage.setItem('raqeeb_notes_seen', String(Date.now() / 1000));
  $('#note-count').hidden = !fresh || onProfile; $('#note-count').textContent = fresh;
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
  setToken(null); ME = null; PROFILE = null; BLOCKS = null; reconnect(); loadProfile(); loadMyReports(); renderHello();
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
  try { DEMO = await api('/api/public/demo'); } catch { /* demo info unavailable */ }
  if (TOKEN) { try { ME = await api('/api/auth/me'); if (ME.role !== 'citizen') { setToken(null); ME = null; } } catch { ME = null; } }
  applyLang(); renderDemoCitizen();
  const want = decodeURIComponent((location.hash.match(/demo=([^&]+)/) || [])[1] || '');
  const acct = DEMO.accounts?.find(a => a.email === want && a.app === 'protect');
  if (acct && !TOKEN) signIn({ email: acct.email, password: acct.password }).catch(() => {});
  syncProtection(); loadAlerts(); loadBrands().catch(() => {});
  connect();
  if (shared) { $('#input').value = shared; check(shared); }
})();
