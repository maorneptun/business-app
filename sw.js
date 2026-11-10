// נפטון — Service Worker: תמיד מביא את הגרסה העדכנית מהשרת (בלי מטמון הדפדפן), ונופל לעותק השמור רק כשאין אינטרנט
const CACHE = 'neptun-v2';
const SHELL = ['./', 'index.html', 'manifest.webmanifest', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL.map(u => new Request(u, { cache: 'reload' })))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return; // השרת (API) לא עובר דרך המטמון
  const fresh = req.mode === 'navigate' || /\.(html|webmanifest)$|\/$/.test(new URL(req.url).pathname);
  e.respondWith(
    fetch(req, fresh ? { cache: 'no-store' } : undefined).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req).then(r => r || caches.match('index.html')))
  );
});
