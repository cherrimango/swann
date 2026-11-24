// Caches the app shell so SAWNN Protect opens offline. The signed protection package is cached by the app itself
// (localStorage), so blocked sites and numbers are still caught without a connection.
const CACHE = 'sawnn-v3';
const SHELL = ['/app', '/static/shared/tokens.css', '/static/app/app.css', '/static/app/i18n.js', '/static/app/app.js', '/static/app/icon-192.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys()
  .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/') || url.pathname === '/ws') return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request, { ignoreSearch: true })));
});
