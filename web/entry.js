// Entry screen: shows demo accounts only when the server runs in demo mode.
(async () => {
  try {
    const d = await (await fetch('/api/public/demo')).json();
    if (!d.enabled) return;
    const list = document.getElementById('demo-list');
    for (const a of d.accounts) {
      const li = document.createElement('li');
      const b = document.createElement('b'); b.textContent = a.label;
      const e = document.createElement('code'); e.textContent = a.email;
      const p = document.createElement('code'); p.textContent = a.password;
      const go = document.createElement('a');
      go.href = (a.app === 'command' ? '/command' : '/app') + '#demo=' + encodeURIComponent(a.email);
      go.textContent = a.app === 'command' ? 'Sign in to Command as this user' : 'Open Protect as this user';
      li.append(b, e, p, go);
      list.append(li);
    }
    document.getElementById('demo').hidden = false;
  } catch { /* offline: the two doors still work */ }
})();
