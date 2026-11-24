// Caches the app shell so the checker opens instantly; checks themselves always go to the network.
const CACHE = 'raqeeb-v1';
const SHELL = ['/app', '/static/app/app.css', '/static/app/app.js', '/static/app/icon-192.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL))));
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/') || url.pathname === '/ws') return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request, { ignoreSearch: true })));
});
