// VRT1 Web Verifier — service worker for genuine offline support.
//
// Strategy: NETWORK-FIRST for same-origin GET requests, falling back to cache
// when offline. This is a deliberate choice for a verifier people must trust:
// when online, users ALWAYS receive the latest deployed code (no risk of a stale
// or poisoned cached copy lingering); when offline, they get the last-known-good
// cached version so verification still works with no connection.
//
// Core assets are precached on install so the very first offline load works.
// Bump CACHE_VERSION on each deploy that changes these files.

const CACHE_VERSION = 'vrt1-verifier-v7';
const CORE_ASSETS = ['./', './index.html', './noble-secp256k1.bundle.mjs', './assets/veritas-hero.jpg', './assets/veritas-seal.jpg'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then((cache) => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  // Only handle same-origin GETs; let everything else (e.g. the GitHub links) pass through.
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        // Cache a fresh copy for offline use, then return the live response.
        const copy = res.clone();
        caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy));
        return res;
      })
      .catch(() =>
        // Offline: serve from cache, falling back to the app shell for navigations.
        caches.match(req).then((cached) => cached || caches.match('./index.html'))
      )
  );
});
