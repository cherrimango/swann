// RAQEEB resident app (installable web app). All text from the network is inserted with textContent.
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const T = {
  en: {
    checkTitle: 'Check before you tap', checkLede: 'Paste a link or a whole message. RAQEEB tells you if it’s a scam and why.',
    inputLabel: 'Link or message', inputPh: 'Paste a link or a message you received', checkBtn: 'Check it', qrBtn: 'Scan a QR code',
    qrHint: 'Point the camera at the QR code', cancel: 'Cancel', tipsTitle: 'Remember',
    tip1: 'No bank or government entity asks for your OTP or UAE PASS approval by phone.',
    tip2: 'Fines, tolls and parcel fees are paid in the official app, not through a link.',
    tip3: 'A price far below the official one is the most common ticket scam.',
    alertsTitle: 'Scam alerts', alertsLede: 'When police block a new scam, it reaches your phone here instantly.',
    notifyBtn: 'Turn on alert notifications', notifyOn: 'Alert notifications are on',
    guardTitle: 'UAE PASS guard',
    guardLede: 'The most damaging scam in the UAE: a fake official calls and asks you to approve a login. On Android, RAQEEB sees the call and the approval request together, and stops you before you tap approve.',
    onCall: 'Simulate: I’m on a call with an unknown number', simulateBtn: 'Simulate a UAE PASS approval request',
    guardNote: 'This is a demo of the Android guard. It doesn’t connect to UAE PASS.',
    tabCheck: 'Check', tabAlerts: 'Alerts', tabGuard: 'Guard', reportBtn: 'Report to Aman', close: 'Close',
    emirateLabel: 'Your emirate', sendReport: 'Send report', amanAlso: 'You can also contact Aman directly:',
    reportDone: 'Report sent. Thank you — it helps protect others.',
    toEyebrow: 'RAQEEB stopped an approval', toTitle: 'Someone is trying to log in as you.',
    toBody: 'You’re on a call with an unknown number and a UAE PASS approval just arrived. Real officials never ask you to approve a login. Hang up first.',
    toDeny: 'I didn’t ask for this. Decline', toAllow: 'It was me',
    scam: 'Scam', suspicious: 'Be careful', safe: 'Looks safe', pretends: n => `Pretends to be ${n}`,
    thisLink: 'This link', official: 'Official', checking: 'Checking…', empty: 'Paste a link or message first.',
    noAlerts: 'No alerts yet. New blocks appear here the moment police push them.',
    blockedNew: 'New scam blocked in the UAE', blockedFor: b => b ? `Impersonating ${b}. Blocked on your phone.` : 'Blocked on your phone.',
    guardOff: 'No call is active, so the approval would go through. The guard steps in only during calls.',
    declined: 'Declined. Never share codes or approvals with a caller. You can report the number to Aman: 8002626.',
    adviceScam: 'Don’t open it or pay. Delete the message and report it.', adviceWarn: 'Don’t enter any details. Open the service from its official app instead.',
    adviceSafe: 'No scam signs found. Still, pay and log in only through official apps.',
    noQr: 'This browser can’t scan QR codes. Try Chrome on Android, or paste the link instead.', qrFound: 'QR code found: checking it',
    unicodeNote: u => `“${u.char}” is not a normal letter: ${u.name}.`, similar: p => `${p}% similar to the official address.`,
    offline: 'Can’t reach RAQEEB right now. Check your connection.',
  },
  ar: {
    checkTitle: 'تحقّق قبل أن تضغط', checkLede: 'الصق رابطاً أو رسالة كاملة، وسيخبرك رقيب إن كانت احتيالاً ولماذا.',
    inputLabel: 'رابط أو رسالة', inputPh: 'الصق رابطاً أو رسالة وصلتك', checkBtn: 'تحقّق', qrBtn: 'امسح رمز QR',
    qrHint: 'وجّه الكاميرا نحو رمز QR', cancel: 'إلغاء', tipsTitle: 'تذكّر',
    tip1: 'لا يطلب أي بنك أو جهة حكومية رمز التحقق أو موافقة الهوية الرقمية عبر الهاتف.',
    tip2: 'تُدفع المخالفات والتعرفة ورسوم الطرود من التطبيق الرسمي، لا عبر رابط.',
    tip3: 'السعر الأقل بكثير من السعر الرسمي هو أكثر احتيالات التذاكر شيوعاً.',
    alertsTitle: 'تنبيهات الاحتيال', alertsLede: 'عندما تحظر الشرطة احتيالاً جديداً، يصل إلى هاتفك هنا فوراً.',
    notifyBtn: 'فعّل إشعارات التنبيه', notifyOn: 'إشعارات التنبيه مفعّلة',
    guardTitle: 'حارس الهوية الرقمية',
    guardLede: 'أخطر احتيال في الإمارات: منتحل صفة رسمية يتصل ويطلب منك الموافقة على تسجيل دخول. على أندرويد، يرى رقيب المكالمة وطلب الموافقة معاً، ويوقفك قبل أن تضغط موافقة.',
    onCall: 'محاكاة: أنا في مكالمة مع رقم مجهول', simulateBtn: 'محاكاة طلب موافقة من الهوية الرقمية',
    guardNote: 'هذا عرض تجريبي لحارس أندرويد، ولا يتصل بالهوية الرقمية.',
    tabCheck: 'تحقّق', tabAlerts: 'التنبيهات', tabGuard: 'الحارس', reportBtn: 'أبلغ خدمة أمان', close: 'إغلاق',
    emirateLabel: 'إمارتك', sendReport: 'أرسل البلاغ', amanAlso: 'يمكنك أيضاً التواصل مع أمان مباشرة:',
    reportDone: 'تم إرسال البلاغ. شكراً لك، فهو يحمي الآخرين.',
    toEyebrow: 'رقيب أوقف طلب موافقة', toTitle: 'شخص ما يحاول تسجيل الدخول باسمك.',
    toBody: 'أنت في مكالمة مع رقم مجهول ووصل للتو طلب موافقة من الهوية الرقمية. الجهات الرسمية لا تطلب منك الموافقة على تسجيل دخول. أنهِ المكالمة أولاً.',
    toDeny: 'لم أطلب ذلك. ارفض', toAllow: 'أنا من طلب',
    scam: 'احتيال', suspicious: 'احذر', safe: 'يبدو آمناً', pretends: n => `ينتحل صفة ${n}`,
    thisLink: 'هذا الرابط', official: 'الرسمي', checking: 'جارٍ التحقق…', empty: 'الصق رابطاً أو رسالة أولاً.',
    noAlerts: 'لا توجد تنبيهات بعد. يظهر كل حظر جديد هنا لحظة إرساله من الشرطة.',
    blockedNew: 'تم حظر احتيال جديد في الإمارات', blockedFor: b => b ? `ينتحل صفة ${b}. محظور على هاتفك.` : 'محظور على هاتفك.',
    guardOff: 'لا توجد مكالمة نشطة، لذلك ستتم الموافقة. يتدخل الحارس أثناء المكالمات فقط.',
    declined: 'تم الرفض. لا تشارك الرموز أو الموافقات مع أي متصل. يمكنك الإبلاغ عن الرقم لدى أمان: 8002626.',
    adviceScam: 'لا تفتحه ولا تدفع. احذف الرسالة وأبلغ عنها.', adviceWarn: 'لا تُدخل أي بيانات. افتح الخدمة من تطبيقها الرسمي بدلاً من ذلك.',
    adviceSafe: 'لا توجد علامات احتيال. ومع ذلك، ادفع وسجّل الدخول عبر التطبيقات الرسمية فقط.',
    noQr: 'هذا المتصفح لا يدعم مسح رموز QR. جرّب كروم على أندرويد أو الصق الرابط.', qrFound: 'تم العثور على رمز QR: جارٍ التحقق',
    unicodeNote: u => `الحرف «${u.char}» ليس حرفاً عادياً: ${u.name}.`, similar: p => `مشابه للعنوان الرسمي بنسبة ${p}٪.`,
    offline: 'تعذّر الوصول إلى رقيب الآن. تحقّق من اتصالك.',
  },
};
let lang = localStorage.getItem('raqeeb-lang') || 'en';
const t = (k, ...a) => { const v = T[lang][k]; return typeof v === 'function' ? v(...a) : v; };

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  $$('[data-i]').forEach(el => { el.textContent = t(el.dataset.i); });
  $$('[data-ph]').forEach(el => { el.placeholder = t(el.dataset.ph); });
  $('#lang').textContent = lang === 'ar' ? 'English' : 'عربي';
  renderAlerts();
}
$('#lang').addEventListener('click', () => { lang = lang === 'ar' ? 'en' : 'ar'; localStorage.setItem('raqeeb-lang', lang); applyLang(); });

/* tabs */
$$('.tabs button').forEach(b => b.addEventListener('click', () => {
  $$('.tabs button').forEach(x => x.classList.toggle('on', x === b));
  $$('.tab').forEach(x => x.classList.toggle('on', x.id === `t-${b.dataset.tab}`));
  if (b.dataset.tab === 'alerts') { unseen = 0; updateCount(); }
}));

function banner(title, text, ms = 6000) {
  const el = $('#banner');
  el.replaceChildren(Object.assign(document.createElement('b'), { textContent: title }), document.createTextNode(text));
  el.hidden = false;
  clearTimeout(banner.tm);
  banner.tm = setTimeout(() => { el.hidden = true; }, ms);
}

/* checking */
const looksLikeLink = s => !/\s/.test(s.trim()) && /[.]/.test(s);
let lastInput = '', lastResult = null;

$('#check-form').addEventListener('submit', e => { e.preventDefault(); check($('#input').value); });
async function check(raw) {
  const text = (raw || '').trim();
  if (!text) { banner('', t('empty'), 3000); return; }
  lastInput = text;
  const btn = $('#check-form .go'); btn.textContent = t('checking'); btn.disabled = true;
  try {
    let r;
    if (looksLikeLink(text)) {
      const link = await (await fetch(`/api/check?url=${encodeURIComponent(text)}`)).json();
      r = { kind: 'link', verdict: link.verdict === 'phishing' ? 'scam' : link.verdict, link, reasons: link.reasons };
    } else {
      const m = await (await fetch('/api/check-message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) })).json();
      const worst = [...m.links].sort((a, b) => b.risk_score - a.risk_score)[0];
      r = { kind: 'message', verdict: m.verdict === 'looks safe' ? 'safe' : m.verdict, link: worst, msg: m,
            reasons: [...m.script_signals, ...(worst ? worst.reasons : [])] };
    }
    lastResult = r;
    showVerdict(r);
  } catch { banner('', t('offline')); }
  finally { btn.textContent = t('checkBtn'); btn.disabled = false; }
}

function seg(segs) {
  const span = document.createElement('span'); span.className = 'host';
  segs.forEach(s => { if (s.type === 'same') span.append(s.text); else { const x = document.createElement('span'); x.className = s.type; x.textContent = s.text; span.append(x); } });
  return span;
}
function row(label, segs) {
  const d = document.createElement('div'); d.className = 'row';
  const l = document.createElement('span'); l.className = 'lbl'; l.textContent = label;
  d.append(l, seg(segs)); return d;
}

function showVerdict(r) {
  const sheet = $('#verdict');
  sheet.className = `sheet ${r.verdict}`;
  $('#v-word').textContent = t(r.verdict);
  const b = r.link?.impersonated_brand;
  $('#v-brand').textContent = b ? t('pretends', lang === 'ar' ? b.name_ar : b.name) : '';
  const twin = $('#v-twin'); twin.replaceChildren();
  if (b?.twin) {
    twin.append(row(t('thisLink'), b.twin.scam_segments), row(t('official'), b.twin.official_segments));
    const note = document.createElement('p'); note.className = 'note';
    note.textContent = b.twin.unicode_tricks.length ? t('unicodeNote', b.twin.unicode_tricks[0]) : t('similar', Math.round(b.twin.similarity * 100));
    twin.append(note);
  }
  const seen = new Set();
  $('#v-reasons').replaceChildren(...r.reasons.filter(x => !x.code?.startsWith('ml:') || r.reasons.length < 3)
    .map(x => x[lang]).filter(x => x && !seen.has(x) && seen.add(x)).slice(0, 5)
    .map(txt => Object.assign(document.createElement('li'), { textContent: txt })));
  $('#v-advice').textContent = r.msg ? r.msg[`advice_${lang}`] : t(r.verdict === 'scam' ? 'adviceScam' : r.verdict === 'suspicious' ? 'adviceWarn' : 'adviceSafe');
  $('#v-report').hidden = r.verdict === 'safe';
  $('#report-box').hidden = true; $('#report-done').hidden = true;
  sheet.hidden = false; sheet.scrollTop = 0;
  if (r.verdict === 'scam') navigator.vibrate?.([120, 60, 120]);
}
$('#v-close').addEventListener('click', () => { $('#verdict').hidden = true; });
$('#v-report').addEventListener('click', () => { $('#report-box').hidden = false; });
$('#send-report').addEventListener('click', async () => {
  await fetch('/api/check-message', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: lastInput, report: true, emirate: $('#emirate').value }) });
  $('#report-done').hidden = false;
});

/* QR codes (quishing: fake parking and payment QR stickers) */
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

/* alerts pushed by police (antibodies) */
let ALERTS = [], unseen = 0;
function updateCount() { const c = $('#alert-count'); c.hidden = !unseen; c.textContent = unseen; }
function renderAlerts(freshDomain) {
  const ol = $('#alerts');
  if (!ALERTS.length) { const li = document.createElement('li'); li.className = 'empty'; li.textContent = t('noAlerts'); ol.replaceChildren(li); return; }
  ol.replaceChildren(...ALERTS.map(a => {
    const li = document.createElement('li'); if (a.domain === freshDomain) li.className = 'new';
    const b = document.createElement('b'); b.textContent = a.domain;
    const p = document.createElement('span'); p.textContent = t('blockedFor', a.brand);
    const w = document.createElement('div'); w.className = 'when'; w.textContent = new Date(a.ts * 1000).toLocaleTimeString(lang === 'ar' ? 'ar-AE' : 'en-AE', { hour: '2-digit', minute: '2-digit' });
    li.append(b, p, w); return li;
  }));
}
async function loadAlerts() {
  try { ALERTS = (await (await fetch('/api/blocklist')).json()).map(x => ({ domain: x.domain, brand: x.brand, ts: x.ts })); } catch { ALERTS = []; }
  renderAlerts();
}
$('#notify').addEventListener('click', async () => {
  if (!('Notification' in window)) return;
  if (await Notification.requestPermission() === 'granted') $('#notify').textContent = t('notifyOn');
});
function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onclose = () => setTimeout(connect, 2000);
  ws.onmessage = ev => {
    const { event, data } = JSON.parse(ev.data);
    if (event !== 'antibody') return;
    ALERTS.unshift({ domain: data.domain, brand: data.brand, ts: Date.now() / 1000 });
    unseen++; updateCount(); renderAlerts(data.domain);
    banner(t('blockedNew'), `${data.domain} · ${t('blockedFor', data.brand)}`);
    navigator.vibrate?.([200, 80, 200]);
    if ('Notification' in window && Notification.permission === 'granted') {
      navigator.serviceWorker?.ready.then(reg => reg.showNotification(t('blockedNew'), { body: `${data.domain}\n${t('blockedFor', data.brand)}`, icon: '/static/app/icon-192.png' }));
    }
  };
}

/* UAE PASS guard demo */
$('#simulate').addEventListener('click', () => {
  if (!$('#oncall').checked) { banner('', t('guardOff')); return; }
  setTimeout(() => { $('#takeover').hidden = false; navigator.vibrate?.([300, 100, 300, 100, 300]); }, 900);
});
$('#to-deny').addEventListener('click', () => { $('#takeover').hidden = true; banner('', t('declined'), 8000); });
$('#to-allow').addEventListener('click', () => { $('#takeover').hidden = true; });

/* shared into the app from another app (Web Share Target) */
const qs = new URLSearchParams(location.search);
const shared = [qs.get('title'), qs.get('text'), qs.get('url')].filter(Boolean).join(' ');

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
applyLang(); loadAlerts(); connect();
if (shared) { $('#input').value = shared; check(shared); }
