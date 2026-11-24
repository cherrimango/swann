// SAWNN Command: language switching, and the SAWNN workspaces (discovery engine, sandbox parameters, citizen alerts,
// models, fourteen agents). Uses the helpers defined in command.js (h, $, $$, api, toast, act?, loaders, can, show).
const CT = {
  en: {},
  ar: {
    wsOps: 'العمليات', wsIntel: 'الاستخبارات', wsInv: 'التحقيقات', wsResp: 'الاستجابة', wsSys: 'النظام', full: 'ملء الشاشة',
    nOverview: 'نظرة عامة', nBriefing: 'تقارير الاستخبارات', nDemo: 'سيناريو العرض', nFeed: 'استخبارات التهديدات المباشرة',
    nDiscovery: 'محرك اكتشاف التهديدات', nCampaigns: 'حملات الاحتيال', nForecast: 'الاستخبارات الموسمية', nDomain: 'تحليل الروابط والنطاقات',
    nThreats: 'التحقق من التهديدات', nReports: 'بلاغات المواطنين', nAgents: 'وكلاء الذكاء الاصطناعي', nSandbox: 'إعدادات البيئة المعزولة',
    nAlerts: 'تنبيهات المواطنين', nProtection: 'الحظر والتوزيع', nCommunity: 'الحماة والمجتمع', nModels: 'النماذج والتقييم',
    nUsers: 'الإدارة', nAudit: 'سجلات التدقيق', loginTitle: 'كوماند', loginSub: 'للمسؤولين والمحللين المخوّلين. يتم تسجيل كل إجراء في سجل التدقيق.',
    email: 'البريد الإلكتروني', password: 'كلمة المرور', signIn: 'تسجيل الدخول', signOut: 'تسجيل الخروج',
  },
};
SawnnLang.mount(CT);
const L = (en, ar) => (SawnnLang.get() === 'ar' ? ar : en);
const localTime = ts => ts ? new Date(ts * 1000).toLocaleString(SawnnLang.get() === 'ar' ? 'ar-AE' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '–';
const busy = async (btn, fn) => { btn.disabled = true; try { return await fn(); } catch (e) { toast(L('Action failed', 'فشل الإجراء'), e.message); } finally { btn.disabled = false; } };

// sortable tables: click a header to sort by that column
document.addEventListener('click', e => {
  const th = e.target.closest('table.sortable th');
  if (!th) return;
  const tb = th.closest('table').tBodies[0], i = [...th.parentNode.children].indexOf(th), dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
  th.parentNode.querySelectorAll('th').forEach(x => delete x.dataset.dir); th.dataset.dir = dir;
  const val = r => { const t = r.children[i]?.dataset.v ?? r.children[i]?.textContent ?? ''; const n = parseFloat(t); return isNaN(n) ? t : n; };
  [...tb.rows].sort((a, b) => (val(a) > val(b) ? 1 : -1) * (dir === 'asc' ? 1 : -1)).forEach(r => tb.append(r));
});

/* ---------------- threat discovery engine ---------------- */
loaders.discovery = async () => {
  const d = (await api('/api/v1/intelligence/sources/status')).discovery;
  const k = d.indicators;
  $('#d-kpis').replaceChildren(...[[L('Indicators stored', 'المؤشرات المخزنة'), k.total], [L('New in 24 h', 'جديدة خلال 24 ساعة'), k.new_24h],
    [L('Unverified leads', 'خيوط غير موثقة'), k.unverified], [L('Analyst-verified', 'موثقة من محلل'), k.verified],
    [L('Failed sources', 'مصادر فاشلة'), d.sources.filter(s => s.last_run && s.last_run.status !== 'ok').length]]
    .map(([a, b]) => h('div', {}, h('dt', {}, a), h('dd', {}, b))));
  const sc = d.scheduler;
  $('#d-sched').textContent = sc.enabled ? L(`Scheduled every ${sc.interval_min} min · next run ${localTime(sc.next_run)}`, `مجدول كل ${sc.interval_min} دقيقة · التشغيل التالي ${localTime(sc.next_run)}`)
    : L('Scheduler off (set SAWNN_DISCOVERY_ENABLED=1). Collections run when you press Collect now.', 'الجدولة متوقفة (اضبط SAWNN_DISCOVERY_ENABLED=1).');
  $('#d-rows').replaceChildren(...d.sources.map(s => h('tr', {}, h('td', {}, s.name), h('td', {}, h('span', { class: `health ${s.health.replace(/\s/g, '_')}` }, s.health === 'blocked_missing_key' ? L(`needs ${s.requires_key}`, `يتطلب ${s.requires_key}`) : s.health)),
    h('td', { 'data-v': s.last_success || 0 }, localTime(s.last_success)), h('td', { 'data-v': s.last_run?.finished || 0 }, localTime(s.last_run?.finished)),
    h('td', {}, s.last_run?.collected ?? '–'), h('td', {}, s.last_run?.new_indicators ?? '–'), h('td', {}, s.last_run?.duplicates ?? '–'), h('td', {}, s.indicators_stored), h('td', { class: 'meta' }, s.terms))));
  $('#d-runs').replaceChildren(...(d.recent_runs.length ? d.recent_runs.map(r => h('tr', {}, h('td', {}, localTime(r.finished)), h('td', {}, r.source), h('td', {}, r.status),
    h('td', {}, r.new_indicators), h('td', { class: 'meta' }, r.error || ''))) : [h('tr', {}, h('td', { colspan: 5, class: 'meta' }, L('No collections yet.', 'لا توجد عمليات جمع بعد.')))]));
};
$('#d-run').addEventListener('click', e => busy(e.currentTarget, async () => {
  const r = await api('/api/v1/intelligence/discovery/run', {});
  toast(L('Collection finished', 'اكتمل الجمع'), r.runs.map(x => `${x.source}: ${x.status}${x.new_indicators ? ` (+${x.new_indicators})` : ''}`).join(' · '));
  loaders.discovery();
}));

/* ---------------- sandbox configuration ---------------- */
loaders.sandbox = async () => {
  const c = await api('/api/v1/sandbox/configuration');
  $('#sb-config').replaceChildren(h('p', { class: 'meta' }, c.enabled ? (c.engine_available ? L('Sandbox enabled · Chromium available', 'البيئة المعزولة مفعلة') : L('Sandbox enabled · static fallback only', 'مفعلة · وضع الجلب الثابت فقط')) : L('Sandbox disabled', 'البيئة المعزولة معطلة')),
    ...c.groups.map(g => h('article', { class: 'panel' }, h('h3', {}, g.name), h('table', { class: 'table cfg' }, h('tbody', {},
      g.parameters.map(p => h('tr', {}, h('th', {}, p.name), h('td', {}, p.value), h('td', { class: 'meta' }, p.env ? `env ${p.env}` : '')))))))) ;
};
$('#sb-go').addEventListener('click', e => busy(e.currentTarget, async () => {
  const id = $('#sb-id').value.trim();
  if (!id) return;
  const r = await api(`/api/v1/sandbox/${encodeURIComponent(id)}`);
  const pc = r.parameters_collected;
  $('#sb-scan').replaceChildren(h('article', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h3', {}, `${r.scan_id} · ${r.verdict || ''} · ${r.analysis_status || r.status}`), h('span', { class: 'note' }, `${pc.collected}/${pc.total} ${L('parameters collected', 'معامل تم جمعه')}`)),
    pc.sandbox_error ? h('p', { class: 'warn-t' }, `${L('Sandbox', 'البيئة المعزولة')}: ${pc.sandbox_error}`) : null,
    h('ul', { class: 'params' }, pc.parameters.map(p => h('li', { class: p.collected ? 'yes' : 'no' }, `${p.collected ? '✓' : '✗'} ${p.parameter}`))),
    redirectTimeline({ ...r, registered_domain: r.redirects?.hops?.[0]?.registered_domain })));
}));

/* ---------------- citizen alerts ---------------- */
let AL = { list: [], cats: {}, channels: {}, cur: null, filter: '' };
const AL_STATUS = { draft: ['Draft', 'مسودة'], in_review: ['In review', 'قيد المراجعة'], reviewed: ['Reviewed', 'تمت المراجعة'], approved: ['Approved', 'معتمد'],
  published: ['Published', 'منشور'], withdrawn: ['Withdrawn', 'مسحوب'], rejected: ['Changes requested', 'مطلوب تعديل'] };
const stLabel = s => L(...(AL_STATUS[s] || [s, s]));
loaders.alerts = async () => {
  const d = await api('/api/v1/notifications');
  AL.list = d.alerts; AL.cats = d.categories; AL.channels = d.channels;
  $('#al-filter').replaceChildren(...['', ...Object.keys(AL_STATUS)].map(s => h('button', { class: `chip ${AL.filter === s ? 'on' : ''}`, onclick: () => { AL.filter = s; loaders.alerts(); } }, s ? stLabel(s) : L('All', 'الكل'))));
  const items = AL.list.filter(a => !AL.filter || a.status === AL.filter);
  $('#al-list').replaceChildren(...(items.length ? items.map(a => h('li', { class: `al-item sev-${a.severity} ${AL.cur?.id === a.id ? 'sel' : ''}`, tabindex: 0,
    onclick: () => editAlert(a), onkeydown: e => e.key === 'Enter' && editAlert(a) },
    h('b', {}, a.content.en.title || L('(untitled)', '(بدون عنوان)')), h('span', { class: 'meta' }, `${a.id} · ${stLabel(a.status)} · v${a.version}${a.ai_drafted ? ' · AI draft' : ''}`))) :
    [h('li', { class: 'meta' }, L('No alerts yet.', 'لا توجد تنبيهات بعد.'))]));
};
const FIELDS = [['title', 'Title', 'العنوان', 'input'], ['description', 'How the scam works', 'كيف يعمل الاحتيال', 'area'], ['warning_signs', 'Warning signs (one per line)', 'علامات التحذير', 'list'],
  ['what_to_do', 'What to do', 'ماذا تفعل', 'list'], ['never_share', 'Never share', 'لا تشارك أبداً', 'list'], ['official_resources', 'Official resources', 'مصادر رسمية', 'list']];
function alertForm(a) {
  const c = a?.content || { en: {}, ar: {} };
  const langCol = lang => h('div', { class: 'al-col', dir: lang === 'ar' ? 'rtl' : 'ltr', lang }, h('h4', {}, lang === 'ar' ? 'العربية' : 'English'),
    FIELDS.map(([k, en, ar, kind]) => {
      const v = c[lang]?.[k] ?? (kind === 'list' ? [] : '');
      const id = `al-${lang}-${k}`;
      return h('label', { for: id }, lang === 'ar' ? ar : en, kind === 'input' ? h('input', { id, value: v }) :
        h('textarea', { id, rows: kind === 'area' ? 4 : 3 }, Array.isArray(v) ? v.join('\n') : v));
    }));
  const sel = (id, opts, cur) => h('select', { id }, opts.map(([v, t]) => h('option', { value: v, ...(v === cur ? { selected: '' } : {}) }, t)));
  const aud = a?.audience || { kind: 'all', emirates: [] };
  return h('div', { class: 'al-form' },
    h('div', { class: 'al-meta' },
      h('label', {}, L('Category', 'الفئة'), sel('al-cat', Object.entries(AL.cats).map(([k, v]) => [k, L(v[0], v[1])]), a?.category || 'phishing_link')),
      h('label', {}, L('Severity', 'الخطورة'), sel('al-sev', [['low', L('Low', 'منخفضة')], ['medium', L('Medium', 'متوسطة')], ['high', L('High', 'مرتفعة')], ['critical', L('Critical', 'حرجة')]], a?.severity || 'high')),
      h('label', {}, L('Audience', 'الجمهور'), sel('al-aud', [['all', L('All registered citizens', 'جميع المواطنين المسجلين')], ['subscribers', L('Subscribers to this category', 'المشتركون في هذه الفئة')], ['emirate', L('Selected emirates', 'إمارات محددة')]], aud.kind)),
      h('label', {}, L('Emirates (comma-separated)', 'الإمارات'), h('input', { id: 'al-em', value: (aud.emirates || []).join(', '), placeholder: 'Abu Dhabi, Dubai' })),
      h('label', {}, L('Brands or services', 'العلامات أو الخدمات'), h('input', { id: 'al-brands', value: (a?.brands || []).join(', ') })),
      h('fieldset', { class: 'al-ch' }, h('legend', {}, L('Channels', 'القنوات')), Object.entries(AL.channels).map(([ch, ok]) => h('label', {},
        h('input', { type: 'checkbox', value: ch, ...((a?.channels || ['in_app']).includes(ch) ? { checked: '' } : {}) }), ` ${ch.replace('_', '-')}${ok ? '' : L(' (not configured)', ' (غير مهيأ)')}`)))),
    h('div', { class: 'al-cols' }, langCol('en'), langCol('ar')));
}
function readForm() {
  const g = id => $(`#${id}`)?.value || '';
  const content = {};
  for (const lang of ['en', 'ar']) {
    content[lang] = {};
    for (const [k, , , kind] of FIELDS) { const v = g(`al-${lang}-${k}`); content[lang][k] = kind === 'list' ? v.split('\n').map(x => x.trim()).filter(Boolean) : v; }
  }
  return { category: g('al-cat'), severity: g('al-sev'), content, brands: g('al-brands').split(',').map(x => x.trim()).filter(Boolean),
    audience: { kind: g('al-aud'), emirates: g('al-em').split(',').map(x => x.trim()).filter(Boolean) },
    channels: $$('.al-ch input:checked').map(i => i.value) };
}
function preview(a) {
  const card = lang => { const c = a.content[lang]; return h('div', { class: 'al-prev', dir: lang === 'ar' ? 'rtl' : 'ltr', lang },
    h('span', { class: `sev sev-${a.severity}` }, a.severity), h('b', {}, c.title), h('p', {}, c.description),
    c.warning_signs?.length ? h('ul', {}, c.warning_signs.map(x => h('li', {}, x))) : null); };
  return h('div', { class: 'al-prevs' }, card('en'), card('ar'));
}
function editAlert(a, draft) {
  AL.cur = a || null;
  const box = $('#al-editor');
  const editable = !a || ['draft', 'reviewed', 'rejected'].includes(a.status);
  const btn = (label, fn, cls = 'ghost') => h('button', { class: cls, onclick: e => busy(e.currentTarget, fn) }, label);
  const save = async () => { const body = readForm(); const r = a ? await api(`/api/v1/notifications/${a.id}`, body, 'PUT') : await api('/api/v1/notifications', { ...body, ai_drafted: !!draft }); toast(L('Saved', 'تم الحفظ'), `${r.id} v${r.version}`); await loaders.alerts(); editAlert(r); };
  const step = (path, body, msg) => async () => { const r = await api(`/api/v1/notifications/${a.id}/${path}`, (typeof body === 'function' ? body() : body) ?? {}); toast(msg, r.id); await loaders.alerts(); editAlert(r); };
  const actions = [];
  if (editable && can('edit_investigation')) actions.push(btn(L('Save draft', 'حفظ المسودة'), save, 'primary'));
  if (!a && can('edit_investigation')) actions.push(btn(L('Draft with AI', 'صياغة بمساعدة الذكاء الاصطناعي'), async () => {
    const f = readForm(); const d = await api('/api/v1/notifications/draft', { category: f.category, brands: f.brands });
    editAlert({ ...f, content: d.content, status: null }, true); AL.cur = null; toast(L('AI draft ready', 'المسودة جاهزة'), d.notice);
  }));
  if (a?.status === 'draft') actions.push(btn(L('Send for review', 'إرسال للمراجعة'), step('submit', {}, L('Sent for review', 'أرسل للمراجعة'))));
  if (a?.status === 'in_review' && can('verify_threat')) actions.push(btn(L('Mark reviewed', 'اعتماد المراجعة'), step('review', { approve: true }, L('Reviewed', 'تمت المراجعة')), 'primary'),
    h('input', { id: 'al-note', placeholder: L('What should change? (for “Request changes”)', 'ما الذي يجب تعديله؟') }),
    btn(L('Request changes', 'طلب تعديل'), step('review', () => ({ approve: false, note: $('#al-note')?.value || '' }), L('Changes requested', 'طُلب تعديل'))));
  if (a?.status === 'reviewed' && can('approve_threat')) actions.push(btn(L('Approve', 'اعتماد'), step('approve', {}, L('Approved', 'تم الاعتماد')), 'primary'));
  if (a?.status === 'approved' && can('approve_threat')) actions.push(btn(L('Publish to citizens', 'النشر للمواطنين'), step('publish', {}, L('Published', 'تم النشر')), 'primary'));
  if (a?.status === 'published' && can('approve_threat')) actions.push(btn(L('Withdraw', 'سحب'), step('withdraw', {}, L('Withdrawn', 'تم السحب')), 'ghost danger'));
  const trail = a?.id ? h('dl', { class: 'al-trail' }, [[L('Created', 'أنشئ'), a.created_by, a.created], [L('Reviewed', 'روجع'), a.reviewed_by, a.reviewed], [L('Approved', 'اعتمد'), a.approved_by, a.approved],
    [L('Published', 'نشر'), a.published_by, a.published]].map(([k, who, ts]) => h('div', {}, h('dt', {}, k), h('dd', {}, who ? `${who} · ${localTime(ts)}` : '–')))) : null;
  const deliveries = a?.deliveries?.length ? h('table', { class: 'table' }, h('thead', {}, h('tr', {}, [L('Channel', 'القناة'), L('Status', 'الحالة'), L('Recipients', 'المستلمون'), L('Detail', 'التفاصيل')].map(x => h('th', {}, x)))),
    h('tbody', {}, a.deliveries.map(d => h('tr', {}, h('td', {}, d.channel), h('td', {}, d.status), h('td', {}, d.recipients), h('td', { class: 'meta' }, d.detail))))) : null;
  box.replaceChildren(h('div', { class: 'panel-head' }, h('h3', {}, a?.id ? `${a.id} · ${stLabel(a.status)} · v${a.version}` : L('New citizen alert', 'تنبيه جديد للمواطنين')),
    draft || a?.ai_drafted ? h('span', { class: 'note warn-t' }, L('AI-assisted draft: not an official statement until approved', 'مسودة بمساعدة الذكاء الاصطناعي: ليست بياناً رسمياً قبل الاعتماد')) : null),
    a?.review_note ? h('p', { class: 'warn-t' }, `${L('Reviewer note', 'ملاحظة المراجع')}: ${a.review_note}`) : null,
    editable ? alertForm(a) : preview(a), h('div', { class: 'al-actions' }, actions), trail,
    a?.engagement && Object.keys(a.engagement).length ? h('p', { class: 'meta' }, `${L('Engagement', 'التفاعل')}: ${Object.entries(a.engagement).map(([k, v]) => `${k} ${v}`).join(' · ')}`) : null, deliveries);
}
$('#al-new').addEventListener('click', () => editAlert(null));
window.newAlertFromThreat = t => { show('alerts'); editAlert({ category: 'phishing_link', severity: t.severity || 'high', brands: t.brand ? [t.brand] : [], content: { en: {}, ar: {} }, status: null, threat_ids: [t.id] }); AL.cur = null; };

/* ---------------- models ---------------- */
loaders.models = async () => {
  const m = await api('/api/v1/models/metrics');
  const ev = m.evaluation_sawnn?.evaluation, vd = m.evaluation_verdicts;
  const pct = x => x == null ? '–' : `${(x * 100).toFixed(2)}%`;
  const row = (name, x) => h('tr', {}, h('td', {}, name), ...['precision', 'recall', 'f1', 'fpr', 'roc_auc', 'pr_auc'].map(k => h('td', { 'data-v': x?.[k] ?? -1 }, x?.[k] == null ? '–' : ['fpr'].includes(k) ? pct(x[k]) : x[k])));
  const verdictRow = (name, v) => v ? h('tr', {}, h('td', {}, name), h('td', {}, pct(v.phishing_marked_safe)), h('td', {}, pct(v.phishing_flagged_malicious_or_suspicious)),
    h('td', {}, pct(v.legitimate_flagged_malicious_or_suspicious)), h('td', {}, pct(v.legitimate_marked_safe))) : null;
  $('#m-body').replaceChildren(
    h('dl', { class: 'kpis' }, [[L('Deployed model', 'النموذج المنشور'), m.deployed.model_version], [L('Dataset', 'مجموعة البيانات'), m.deployed.dataset_version],
      [L('Trained', 'تاريخ التدريب'), m.deployed.trained_at], [L('Decision threshold', 'عتبة القرار'), m.deployed.threshold]].map(([a, b]) => h('div', {}, h('dt', {}, a), h('dd', { class: 'small-dd' }, b ?? '–')))),
    vd ? h('article', { class: 'panel' }, h('h3', {}, L('End-to-end verdicts, before and after', 'النتائج الكاملة قبل وبعد')),
      h('p', { class: 'meta' }, `${vd.n_per_class} ${L('phishing and', 'تصيد و')} ${vd.n_per_class} ${L('legitimate URLs from the held-out test split; threat feeds off so detection is measured, not list look-ups.', 'رابطاً مشروعاً من مجموعة الاختبار المعزولة.')}`),
      h('table', { class: 'table' }, h('thead', {}, h('tr', {}, ['', L('Phishing marked SAFE', 'تصيد صُنّف آمناً'), L('Phishing flagged', 'تصيد تم رصده'), L('Legitimate flagged', 'مشروع تم رصده خطأً'), L('Legitimate marked SAFE', 'مشروع صُنّف آمناً')].map(x => h('th', {}, x)))),
        h('tbody', {}, verdictRow(L('Previous version (2.1)', 'الإصدار السابق (2.1)'), vd.raqeeb_2_1), verdictRow('SAWNN', vd.mira), verdictRow(L('SAWNN · UAE set', 'صون · مجموعة الإمارات'), vd.uae_eval_mira)))) : null,
    ev ? h('article', { class: 'panel' }, h('h3', {}, L('URL model on the held-out test split', 'نموذج الروابط على مجموعة الاختبار')),
      h('table', { class: 'table sortable' }, h('thead', {}, h('tr', {}, ['Model', 'Precision', 'Recall', 'F1', 'FPR', 'ROC-AUC', 'PR-AUC'].map(x => h('th', {}, x)))),
        h('tbody', {}, row(L('SAWNN stacked model (deployed)', 'نموذج صون المنشور'), ev.main), row(L('SAWNN at 0.1% FPR operating point', 'صون عند نقطة 0.1%'), ev['strict_0.1pct_fpr']),
          ...Object.entries(ev.baselines_same_test_set).map(([k, v]) => row(k === 'raqeeb_2_1_hostname_model' ? L('previous version 2.1, hostname model', 'الإصدار السابق 2.1') : k.replaceAll('_', ' '), v)))),
      h('p', { class: 'meta' }, `${L('Unseen OpenPhish snapshot recall', 'الاستدعاء على لقطة OpenPhish جديدة')}: ${pct(ev.openphish_fresh_unseen?.recall_at_threshold)} (n=${ev.openphish_fresh_unseen?.n}) · ${L('latency', 'زمن الاستجابة')} ${ev.openphish_fresh_unseen?.latency_ms_per_url} ms/URL`),
      h('details', {}, h('summary', {}, L('By source and by URL shape', 'حسب المصدر وشكل الرابط')), h('table', { class: 'table' }, h('tbody', {},
        Object.entries({ ...ev.by_source, ...ev.with_path_vs_hostname_only }).map(([k, v]) => h('tr', {}, h('td', {}, k), h('td', {}, `n=${v.n}`), h('td', {}, `recall ${v.recall}`), h('td', {}, `FPR ${pct(v.fpr)}`))))))) : null,
    h('article', { class: 'panel' }, h('h3', {}, L('Limitations', 'القيود')), h('ul', { class: 'limits' }, (m.evaluation_sawnn?.limitations || []).map(x => h('li', {}, x)))));
};

/* ---------------- fourteen agents ---------------- */
const _agentsLoader = loaders.agents;
loaders.agents = async () => {
  const list = await api('/api/v1/agents');
  $('#ag14').replaceChildren(...list.map(a => {
    const inp = a.input ? h('input', { placeholder: a.input, 'aria-label': `${a.name} input` }) : null;
    const b = h('button', { class: 'ghost small', onclick: () => busy(b, async () => {
      const r = await api(`/api/v1/agents/${a.id}/run`, { input: inp?.value || null });
      $('#ag-out').replaceChildren(h('article', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h3', {}, `${r.agent} — ${r.task}`), h('span', { class: 'note' }, `${localTime(Date.parse(r.timestamp) / 1000)} · ${r.duration_seconds}s`)),
        h('dl', { class: 'kv' }, [[L('Result', 'النتيجة'), JSON.stringify(r.result)], [L('Confidence', 'الثقة'), r.confidence ?? L('not applicable', 'غير منطبق')], [L('Source', 'المصدر'), r.source],
          [L('Recommended action', 'الإجراء الموصى به'), r.recommended_action], [L('Limitations', 'القيود'), r.limitations.join(' ')]].map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, String(v))))),
        h('details', {}, h('summary', {}, L('Evidence', 'الأدلة')), h('pre', { class: 'text' }, JSON.stringify(r.evidence, null, 2)))));
    }) }, L('Run', 'تشغيل'));
    return h('div', { class: 'ag-card' }, h('b', {}, a.name), h('span', { class: 'meta' }, `${a.runs} ${L('runs', 'تشغيل')}${a.last_run ? ' · ' + localTime(a.last_run) : ''}`), h('div', { class: 'ag-row' }, inp, b));
  }));
  await _agentsLoader?.().catch(() => {});
};

/* ---------------- overview: engine, sources and sandbox health from the backend ---------------- */
const _ovLoader = loaders.overview;
loaders.overview = async () => {
  await _ovLoader();
  const [m, src, scans] = await Promise.all([api('/api/v1/models/metrics').catch(() => null), api('/api/v1/intelligence/sources/status').catch(() => null),
    api('/api/v1/scans').catch(() => [])]);
  const deep = scans.filter(s => s.mode === 'deep'), done = deep.filter(s => s.status === 'complete');
  const vd = m?.evaluation_verdicts?.mira, ev = m?.evaluation_sawnn?.evaluation?.main;
  const srcs = src?.discovery?.sources || [];
  const tile = (k, v, note, cls = '') => h('div', { class: `ov-tile ${cls}` }, h('span', { class: 'ov-k' }, k), h('b', {}, v), h('span', { class: 'meta' }, note));
  $('#ov-mira').replaceChildren(
    tile(L('Detection model', 'نموذج الكشف'), ev ? `${(ev.recall * 100).toFixed(1)}% ${L('recall', 'استدعاء')}` : '–', ev ? `${(ev.fpr * 100).toFixed(2)}% ${L('false positives · held-out test', 'إنذارات خاطئة')}` : L('no evaluation file', 'لا يوجد تقييم')),
    tile(L('Phishing marked SAFE', 'تصيد صُنّف آمناً'), vd ? `${(vd.phishing_marked_safe * 100).toFixed(1)}%` : '–', L('end-to-end verdicts, held-out test', 'النتائج الكاملة على الاختبار'), 'good'),
    tile(L('Intelligence sources', 'مصادر الاستخبارات'), `${srcs.filter(s => s.health === 'healthy').length}/${srcs.length} ${L('healthy', 'سليمة')}`,
      srcs.some(s => s.health !== 'healthy') ? L('open Threat discovery engine for errors', 'افتح محرك الاكتشاف للأخطاء') : L('all feeds collecting', 'جميع المصادر تعمل'), srcs.every(s => s.health === 'healthy') ? 'good' : 'warn'),
    tile(L('Sandbox activity', 'نشاط البيئة المعزولة'), `${deep.length} ${L('deep scans', 'فحص عميق')}`, `${done.length} ${L('completed', 'مكتمل')} · ${deep.filter(s => s.status === 'running').length} ${L('running', 'قيد التشغيل')} · ${deep.filter(s => s.status === 'failed').length} ${L('failed', 'فاشل')}`));
};

/* view headings in Arabic (detailed analyst tables stay in English; see docs/STATUS.md) */
const VIEW_AR = { overview: 'نظرة عامة', threats: 'التحقق من التهديدات', reports: 'بلاغات المواطنين', feed: 'استخبارات التهديدات المباشرة',
  domain: 'تحليل الروابط والنطاقات', campaigns: 'حملات الاحتيال', forecast: 'الاستخبارات الموسمية', briefing: 'تقارير الاستخبارات', agents: 'وكلاء الذكاء الاصطناعي',
  protection: 'الحظر والتوزيع', community: 'الحماة والمجتمع', audit: 'سجلات التدقيق', users: 'الإدارة', demo: 'سيناريو العرض',
  discovery: 'محرك اكتشاف التهديدات', sandbox: 'إعدادات البيئة المعزولة ومعاملات التحليل', alerts: 'تنبيهات المواطنين', models: 'النماذج والتقييم' };
function headings() {
  $$('.view').forEach(v => {
    const h2 = v.querySelector('h2'); if (!h2) return;
    h2.dataset.en = h2.dataset.en || h2.textContent;
    h2.textContent = SawnnLang.get() === 'ar' ? (VIEW_AR[v.id.slice(2)] || h2.dataset.en) : h2.dataset.en;
  });
}
document.addEventListener('sawnn:lang', () => { headings(); const on = $('.view.on'); if (on) loaders[on.id.slice(2)]?.().catch(() => {}); });
headings();
