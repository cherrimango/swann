// SAWNN clipboard helpers. Native copy/paste is never intercepted; these only add buttons.
// navigator.clipboard needs a secure context (https or localhost). On a phone opening the laptop over plain
// http://<lan-ip>, copy falls back to a hidden textarea and Paste asks the user to long-press instead.
(function () {
  function toast(msg, ok) {
    let t = document.getElementById('clip-toast');
    if (!t) { t = document.createElement('div'); t.id = 'clip-toast'; t.setAttribute('role', 'status'); t.setAttribute('aria-live', 'polite'); document.body.append(t); }
    t.textContent = msg; t.className = ok ? 'ok on' : 'err on';
    clearTimeout(t._h); t._h = setTimeout(() => { t.className = ''; }, 2200);
  }
  async function copy(text, labels = {}) {
    const ok = labels.ok || 'Copied', bad = labels.err || 'Couldn’t copy. Select the text and copy it manually.';
    try {
      if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); toast(ok, true); return true; }
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
      document.body.append(ta); ta.select(); ta.setSelectionRange(0, text.length);
      const done = document.execCommand('copy'); ta.remove();
      toast(done ? ok : bad, done); return done;
    } catch { toast(bad, false); return false; }
  }
  async function paste(labels = {}) {
    try {
      if (navigator.clipboard?.readText && window.isSecureContext) return (await navigator.clipboard.readText()) || '';
    } catch { /* permission refused */ }
    toast(labels.err || 'Paste isn’t allowed here. Long-press or right-click the box and choose Paste.', false);
    return null;
  }
  function button(text, getText, labels = {}) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'copy-btn'; b.textContent = labels.button || 'Copy';
    b.setAttribute('aria-label', `${labels.button || 'Copy'}: ${labels.what || ''}`.trim());
    b.addEventListener('click', e => { e.stopPropagation(); copy(typeof getText === 'function' ? getText() : getText, labels); });
    return b;
  }
  window.SawnnClip = { copy, paste, button, toast };
})();
