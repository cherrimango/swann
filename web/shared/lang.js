// SAWNN global language: English or Arabic (more can be added to LANGS). One stored choice ("sawnn-lang") drives the
// entry screen, SAWNN Command, SAWNN Protect and the sign-in prototype. Arabic switches the whole document to RTL.
(function () {
  const LANGS = { en: { dir: 'ltr', label: 'English' }, ar: { dir: 'rtl', label: 'العربية' } };
  const KEY = 'sawnn-lang';
  function get() {
    let v = null;
    try { v = localStorage.getItem(KEY); } catch { /* storage unavailable */ }
    if (!LANGS[v]) v = (navigator.language || 'en').toLowerCase().startsWith('ar') ? 'ar' : 'en';
    return v;
  }
  function apply(dict, lang) {
    document.documentElement.lang = lang;
    document.documentElement.dir = LANGS[lang].dir;
    if (dict) {
      document.querySelectorAll('[data-t]').forEach(el => {
        const v = (dict[lang] || {})[el.dataset.t] ?? (dict.en || {})[el.dataset.t];
        if (v !== undefined) el.textContent = v;
      });
      document.querySelectorAll('[data-t-ph]').forEach(el => {
        const v = (dict[lang] || {})[el.dataset.tPh] ?? (dict.en || {})[el.dataset.tPh];
        if (v !== undefined) el.placeholder = v;
      });
    }
    document.querySelectorAll('.langs button[data-lang]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
  }
  function set(lang, dict) {
    if (!LANGS[lang]) return;
    try { localStorage.setItem(KEY, lang); } catch { /* ignore */ }
    apply(dict, lang);
    document.dispatchEvent(new CustomEvent('sawnn:lang', { detail: lang }));
  }
  function mount(dict) {
    document.querySelectorAll('.langs button[data-lang]').forEach(b => b.addEventListener('click', () => set(b.dataset.lang, dict)));
    apply(dict, get());
  }
  window.SawnnLang = { LANGS, get, set, apply, mount, t: (dict, k) => ((dict[get()] || {})[k] ?? (dict.en || {})[k] ?? k) };
})();
