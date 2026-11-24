// Entry screen: language switch, and demo accounts only when the server runs in demo mode.
const T = {
  en: {},
  ar: {
    h1: 'اكتشف التهديد قبل أن يصل إلى الناس.',
    lede: 'تكتشف ميرا المواقع المزيفة وحملات الاحتيال في الإمارات، وتتيح للمسؤولين المخوّلين التحقق منها، ثم ترسل التحذيرات والحماية المعتمدة إلى كل مواطن.',
    cmdK: 'للمسؤولين والمحللين المخوّلين', cmdD: 'تحقيق في الروابط والحملات، ومراجعة أدلة البيئة المعزولة، واعتماد التهديدات ونشر تنبيهات المواطنين.',
    cmdGo: 'تسجيل الدخول إلى ميرا كوماند', proK: 'للمواطنين والمقيمين',
    proD: 'افحص الروابط والرسائل ولقطات الشاشة ورموز QR وأرقام الهواتف. أبلغ عن الاحتيال وتابع بلاغاتك.', proGo: 'افتح ميرا بروتكت',
    passT: 'نموذج تسجيل الدخول', passK: 'للعرض التوضيحي فقط',
    passD: 'تسجيل دخول محاكى بأسلوب الهوية الوطنية، ومحاكي أمني يعلّم الناس كشف صفحات الدخول المزيفة. لا يطلب أي بيانات دخول حقيقية.',
    passGo: 'افتح النموذج', demoH: 'حسابات العرض التوضيحي', demoNote: 'بيانات دخول للعرض فقط، تظهر لأن الخادم يعمل في وضع العرض. لا تستخدم كلمات المرور هذه في أي مكان آخر.',
    foot: 'هاكاثون ScamShield AI — شرطة أبوظبي × 42 أبوظبي',
  },
};
MiraLang.mount(T);
(async () => {
  try {
    const d = await (await fetch('/api/public/demo')).json();
    if (!d.enabled) return;
    const list = document.getElementById('demo-list');
    const ar = () => MiraLang.get() === 'ar';
    for (const a of d.accounts) {
      const li = document.createElement('li');
      const b = document.createElement('b'); b.textContent = a.label;
      const e = document.createElement('code'); e.textContent = a.email;
      const p = document.createElement('code'); p.textContent = a.password;
      const go = document.createElement('a');
      go.href = (a.app === 'command' ? '/command' : '/app') + '#demo=' + encodeURIComponent(a.email);
      go.textContent = a.app === 'command' ? (ar() ? 'الدخول إلى كوماند بهذا الحساب' : 'Sign in to Command as this user')
        : (ar() ? 'فتح بروتكت بهذا الحساب' : 'Open Protect as this user');
      li.append(b, e, p, go);
      list.append(li);
    }
    document.getElementById('demo').hidden = false;
  } catch { /* offline: the doors still work */ }
})();
