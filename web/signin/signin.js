// SAWNN demo sign-in prototype + security simulator. Everything here is labelled as simulated; link checks call the
// real SAWNN engine (/api/v1/scan). DOM is built with textContent only.
const $ = s => document.querySelector(s);
const h = (tag, attrs = {}, ...kids) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === 'class') el.className = v; else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v); }
  kids.flat().forEach(k => k != null && el.append(k instanceof Node ? k : document.createTextNode(String(k))));
  return el;
};
const T = {
  en: {
    waiting: 'Waiting for approval on the demo phone…', approved: 'Approved. Signing you in…', denied: 'You declined the request. Nothing was shared.',
    expired: 'The request expired. Start again.', off: 'Demo sign-in is switched off on this server (it needs SAWNN_DEMO=1).',
    doneOk: 'Approved. You can return to SAWNN.', doneNo: 'Declined.', needConsent: 'Tick the consent box to approve.',
    checking: 'Checking with SAWNN…', mira: 'What SAWNN detects', run: 'Check this link with SAWNN', verdict: 'Verdict',
    MALICIOUS: 'Dangerous', SUSPICIOUS: 'Be careful', INCONCLUSIVE: 'Not clear yet', SAFE: 'No warning signs', failed: 'The check failed: ',
  },
  ar: {
    band: 'نموذج عرض توضيحي من صون — تسجيل دخول محاكى.', bandD: 'هذا ليس الهوية الرقمية (UAE PASS) وغير متصل بها. لا تُدخل أبداً بيانات دخول حقيقية أو رقم الهوية الإماراتية أو رموز التحقق هنا.',
    tabSignin: 'نموذج تسجيل الدخول', tabSim: 'المحاكي الأمني', tabHow: 'ما الذي تتم محاكاته',
    h1: 'تسجيل الدخول إلى صون', sub: 'مع تطبيق الهوية الرقمية، تمسح رمزاً وتوافق من هاتفك. يعرض هذا النموذج تلك الرحلة باستخدام حسابات العرض في صون فقط.',
    go: 'تسجيل الدخول بالهوية الرقمية (عرض)', qrTag: 'عرض', qrHint: 'امسح الرمز بالهاتف التجريبي على الجانب أو استخدم أزراره. يحتوي الرمز فقط على رقم طلب تجريبي من صون.',
    restart: 'ابدأ من جديد', alt: 'تفضّل البريد وكلمة المرور؟', altC: 'دخول كوماند', altP: 'بروتكت',
    phApp: 'تطبيق هوية تجريبي (محاكى)', phIdle: 'بانتظار طلب تسجيل دخول…', phTitle: 'صون تطلب تسجيل دخولك', phAcct: 'الحساب التجريبي',
    aCit: 'مواطن', aAna: 'محلل جرائم إلكترونية', aAdm: 'مسؤول كوماند', consent: 'شارك اسمي ودوري التجريبيين مع صون', deny: 'رفض', approve: 'موافقة',
    simH: 'اكتشف تسجيل الدخول المزيف', simSub: 'تعرض كل خطوة حيلة يستخدمها المحتالون لتقليد تسجيل الدخول الوطني، وما تكتشفه صون. جميع النطاقات أدناه وهمية، ويتم فحص الروابط بمحرك صون الحقيقي.',
    howH: 'ما الذي يحاكيه هذا النموذج', thStep: 'الخطوة', thHere: 'في هذا النموذج', thReal: 'في تكامل حقيقي معتمد', callsH: 'هل يمكنه إجراء مكالمات؟',
    docs: 'يتبع المسار الإنتاجي وثائق المطورين الرسمية لـ UAE PASS؛ راجع docs/UAE_PASS_INTEGRATION.md في المشروع.',
    waiting: 'بانتظار الموافقة على الهاتف التجريبي…', approved: 'تمت الموافقة. جارٍ تسجيل دخولك…', denied: 'رفضت الطلب. لم تتم مشاركة أي شيء.',
    expired: 'انتهت صلاحية الطلب. ابدأ من جديد.', off: 'تسجيل الدخول التجريبي متوقف على هذا الخادم (يتطلب SAWNN_DEMO=1).',
    doneOk: 'تمت الموافقة. يمكنك العودة إلى صون.', doneNo: 'تم الرفض.', needConsent: 'ضع علامة على مربع الموافقة للمتابعة.',
    checking: 'جارٍ الفحص مع صون…', mira: 'ما تكتشفه صون', run: 'افحص هذا الرابط مع صون', verdict: 'النتيجة',
    MALICIOUS: 'خطير', SUSPICIOUS: 'احذر', INCONCLUSIVE: 'غير واضح بعد', SAFE: 'لا توجد علامات تحذير', failed: 'فشل الفحص: ',
  },
};
const t = k => SawnnLang.t(T, k);
const ar = () => SawnnLang.get() === 'ar';

// sections
document.querySelectorAll('.seg button').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.seg button').forEach(x => x.classList.toggle('on', x === b));
  document.querySelectorAll('.pane').forEach(p => p.classList.toggle('on', p.id === `p-${b.dataset.pane}`));
}));

// ---------- sign-in prototype ----------
let RID = null, timer = null;
async function j(path, body) {
  const r = await fetch(path, { method: body ? 'POST' : 'GET', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(d.detail || r.status), { status: r.status });
  return d;
}
function phone(view) { ['idle', 'req', 'done'].forEach(v => { $(`#ph-${v}`).hidden = v !== view; }); }
$('#go').addEventListener('click', async () => {
  try {
    const d = await j('/api/signin-demo/start', {});
    RID = d.request_id;
    $('#qr').src = `/api/qr?data=${encodeURIComponent(d.qr_payload)}`;
    $('#qr-step').hidden = false; $('#go').hidden = true; $('#restart').hidden = true;
    $('#state').textContent = t('waiting');
    phone('req');
    clearInterval(timer); timer = setInterval(poll, 1200);
  } catch (e) { $('#qr-step').hidden = false; $('#state').textContent = e.status === 403 ? t('off') : String(e.message); }
});
$('#restart').addEventListener('click', () => { $('#go').hidden = false; $('#qr-step').hidden = true; phone('idle'); $('#go').click(); });
async function respond(approve) {
  if (approve && !$('#consent').checked) { $('#state').textContent = t('needConsent'); return; }
  try { await j(`/api/signin-demo/${RID}/respond`, { account: $('#acct').value, approve, consent: $('#consent').checked }); }
  catch (e) { $('#state').textContent = String(e.message); return; }
  phone('done'); $('#ph-done-t').textContent = approve ? t('doneOk') : t('doneNo');
}
$('#approve').addEventListener('click', () => respond(true));
$('#deny').addEventListener('click', () => respond(false));
async function poll() {
  if (!RID) return;
  let d;
  try { d = await j(`/api/signin-demo/${RID}`); } catch { return; }
  if (d.state === 'waiting') return;
  clearInterval(timer);
  $('#state').textContent = t(d.state);
  if (d.state === 'approved' && d.token) {
    // the same session storage the apps already use for automatic sign-in
    if (d.app === 'command') { sessionStorage.setItem('raqeeb_cmd_token', d.token); location.href = '/command'; }
    else { localStorage.setItem('raqeeb_token', d.token); location.href = '/app'; }
  } else { $('#restart').hidden = false; }
}

// ---------- security simulator ----------
const STEPS = [
  { k: 'sms', en: ['A text message creates urgency', 'Your digital ID will be suspended today. Re-verify now: https://uaepass-reverify.top/login'],
    ar: ['رسالة نصية تخلق إحساساً بالاستعجال', 'سيتم إيقاف هويتك الرقمية اليوم. أعد التحقق الآن: https://uaepass-reverify.top/login'],
    url: 'https://uaepass-reverify.top/login',
    tip: ['Official services do not threaten suspension by SMS with a link.', 'الجهات الرسمية لا تهدد بالإيقاف عبر رسالة نصية تحتوي على رابط.'] },
  { k: 'lookalike', en: ['A look-alike address', 'login.uaepass.example-verify.com looks official because it starts with "uaepass", but the site that owns it is example-verify.com.'],
    ar: ['عنوان مشابه', 'يبدو login.uaepass.example-verify.com رسمياً لأنه يبدأ بـ "uaepass"، لكن الموقع المالك هو example-verify.com.'],
    url: 'https://login.uaepass.example-verify.com/auth',
    tip: ['Read the address from the right: the part just before the ending (.com, .ae) is the real owner.', 'اقرأ العنوان من اليمين: الجزء الذي يسبق الامتداد مباشرة هو المالك الحقيقي.'] },
  { k: 'redirect', en: ['A shortened link that hops between sites', 'A short link forwards you through two unrelated domains before the fake page loads. SAWNN follows every hop in a deep scan.'],
    ar: ['رابط مختصر يتنقل بين مواقع', 'يحوّلك الرابط المختصر عبر نطاقين غير مرتبطين قبل ظهور الصفحة المزيفة. تتبع صون كل خطوة في الفحص العميق.'],
    url: 'https://bit.ly/uae-id-renew',
    tip: ['A shortened link hides where it goes. Check it before opening.', 'الرابط المختصر يخفي وجهته. افحصه قبل فتحه.'] },
  { k: 'otp', en: ['A fake page asks for your one-time code', 'The page copies the official design and asks for your Emirates ID number and the OTP you just received.'],
    ar: ['صفحة مزيفة تطلب رمز التحقق', 'تنسخ الصفحة التصميم الرسمي وتطلب رقم الهوية الإماراتية ورمز التحقق الذي وصلك للتو.'],
    url: 'https://uae-digital-id-verify.online/otp',
    tip: ['Never type a one-time code into a page you reached from a message.', 'لا تكتب أبداً رمز تحقق في صفحة وصلت إليها من رسالة.'] },
  { k: 'qr', en: ['A QR code on a poster or in a chat', '"Scan to update your ID." The QR code opens a phishing page; SAWNN Protect decodes the QR image and checks the link before you open it.'],
    ar: ['رمز QR على ملصق أو في محادثة', '"امسح لتحديث هويتك." يفتح الرمز صفحة تصيد؛ يقرأ صون بروتكت صورة الرمز ويفحص الرابط قبل فتحه.'],
    url: 'http://uaepass-update.xyz/qr',
    tip: ['Only scan sign-in codes shown by the service you started.', 'امسح رموز الدخول التي تعرضها الخدمة التي بدأت بها فقط.'] },
  { k: 'app', en: ['A fake app download', 'A message offers a "new ID app" as an APK file outside the official app stores.'],
    ar: ['تنزيل تطبيق مزيف', 'تعرض رسالة "تطبيق هوية جديداً" كملف APK خارج المتاجر الرسمية.'],
    url: 'https://uaepass-app-download.top/uaepass.apk',
    tip: ['Install identity apps only from the official App Store or Google Play listing.', 'ثبّت تطبيقات الهوية من المتجر الرسمي فقط.'] },
  { k: 'call', en: ['A call from "the identity team" (fictional script)', 'Caller: "We noticed a problem with your account. I am sending you a code; read it to me to confirm." — This is a written, synthetic script. SAWNN never places calls.'],
    ar: ['مكالمة من "فريق الهوية" (نص وهمي)', 'المتصل: "لاحظنا مشكلة في حسابك. سأرسل لك رمزاً؛ اقرأه لي للتأكيد." — هذا نص مكتوب ومصطنع. صون لا تجري مكالمات أبداً.'],
    url: null,
    tip: ['No genuine organisation asks you to read a code aloud. Hang up and report the number in SAWNN Protect.', 'لا تطلب أي جهة حقيقية قراءة رمز بصوت عالٍ. أنهِ المكالمة وأبلغ عن الرقم في صون بروتكت.'] },
];
function renderSteps() {
  $('#steps').replaceChildren(...STEPS.map(s => {
    const [title, body] = ar() ? s.ar : s.en;
    const out = h('div', { class: 'det', 'aria-live': 'polite' });
    const li = h('li', { class: 'step glass' }, h('h2', {}, title), h('p', { class: 'scenario' }, body),
      s.url ? h('p', { class: 'url ltr' }, s.url) : null,
      h('p', { class: 'tip' }, ar() ? s.tip[1] : s.tip[0]),
      s.url ? h('button', { class: 'ghost', onclick: () => check(s.url, out) }, t('run')) : null, out);
    return li;
  }));
}
async function check(url, out) {
  out.replaceChildren(h('p', { class: 'hint' }, t('checking')));
  try {
    const r = await j('/api/v1/scan', { url, mode: 'quick' });
    const why = (r.strongest_indicators || []).map(e => ar() ? (e.detail_ar || e.detail_en) : e.detail_en);
    out.replaceChildren(h('div', { class: `res ${r.verdict}` }, h('b', {}, `${t('mira')}: ${t(r.verdict)} · ${Math.round(r.risk_score)}/100`),
      h('ul', {}, why.slice(0, 4).map(w => h('li', {}, w))), h('p', { class: 'hint' }, ar() ? r.recommended_action.ar : r.recommended_action.en)));
  } catch (e) { out.replaceChildren(h('p', { class: 'hint' }, t('failed') + e.message)); }
}

// ---------- what is simulated ----------
const HOW = [
  ['QR code', 'Contains a SAWNN demo request ID, generated by SAWNN', 'Generated by the identity provider for an authorisation request from a registered service provider'],
  ['Phone approval', 'Buttons on the simulated phone on this page', 'The citizen approves in the official identity app on their own phone'],
  ['Consent', 'A checkbox; shares only the demo account name and role', 'The identity provider shows the data the service requested and records consent'],
  ['Account', 'SAWNN demo accounts only (citizen, analyst, administrator)', 'The citizen’s verified identity, mapped to a SAWNN account by the service'],
  ['Result', 'SAWNN issues its own session (hashed token, expiry, logout), exactly like a password sign-in', 'Authorisation code → server-side token exchange with client credentials → validated user info → SAWNN session'],
];
const HOW_AR = [
  ['رمز QR', 'يحتوي على رقم طلب تجريبي من صون', 'يُنشئه مزوّد الهوية لطلب تفويض من مقدم خدمة مسجّل'],
  ['الموافقة من الهاتف', 'أزرار على الهاتف المحاكى في هذه الصفحة', 'يوافق المواطن في تطبيق الهوية الرسمي على هاتفه'],
  ['الموافقة على المشاركة', 'مربع اختيار؛ يشارك اسم الحساب التجريبي ودوره فقط', 'يعرض مزوّد الهوية البيانات المطلوبة ويسجّل الموافقة'],
  ['الحساب', 'حسابات العرض في صون فقط', 'هوية المواطن الموثّقة مرتبطة بحساب في صون'],
  ['النتيجة', 'تُصدر صون جلستها الخاصة (رمز مشفّر، انتهاء صلاحية، تسجيل خروج)', 'رمز تفويض ← تبادل الرمز على الخادم ببيانات العميل ← التحقق من المستخدم ← جلسة صون'],
];
const CALLS = {
  en: ['Simulating a verification call: this page shows a written, synthetic script. No audio is played to anyone and no call is placed.',
       'Detecting suspicious numbers: SAWNN checks a number against reports and analyst-verified threats (Protect → Check a number).',
       'Detecting suspicious call behaviour: the Android app’s call-screening service can reject numbers analysts confirmed, on the phone itself, after the user makes SAWNN the call-screening app. iPhone has no equivalent open API.',
       'Placing calls: SAWNN never places, spoofs or records calls and never contacts people by phone.'],
  ar: ['محاكاة مكالمة تحقق: تعرض هذه الصفحة نصاً مكتوباً ومصطنعاً. لا يتم تشغيل صوت ولا إجراء أي مكالمة.',
       'كشف الأرقام المشبوهة: تفحص صون الرقم مقابل البلاغات والتهديدات الموثّقة.',
       'كشف سلوك المكالمات المشبوه: يمكن لخدمة فحص المكالمات في تطبيق أندرويد رفض الأرقام المؤكدة على الهاتف نفسه بعد أن يجعل المستخدم صون تطبيق فحص المكالمات. لا توجد واجهة مماثلة مفتوحة في آيفون.',
       'إجراء المكالمات: صون لا تجري مكالمات ولا تزوّر أرقام المتصلين ولا تتصل بأي شخص.'],
};
function renderHow() {
  $('#how-rows').replaceChildren(...(ar() ? HOW_AR : HOW).map(r => h('tr', {}, r.map(c => h('td', {}, c)))));
  $('#calls').replaceChildren(...CALLS[ar() ? 'ar' : 'en'].map(c => h('li', {}, c)));
}
document.addEventListener('sawnn:lang', () => { renderSteps(); renderHow(); });
SawnnLang.mount(T);
renderSteps(); renderHow();
