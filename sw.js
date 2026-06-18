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

const CACHE_VERSION = 'vrt1-verifier-v11';
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

  // Videos: Cloudflare Pages serves these as plain 200s with no Accept-Ranges,
  // which disables scrubbing/seeking in the browser. Serve byte-ranges ourselves
  // from a cached full copy so the seek bar works. See serveMedia().
  if (/\.(mp4|webm|m4v|mov|ogg)$/i.test(new URL(req.url).pathname)) {
    event.respondWith(serveMedia(req));
    return;
  }

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

// Range-aware media handler. Fetches the full clip once, caches it, then answers
// each request from that buffer — a real 206 Partial Content for range requests
// (what the <video> seek bar needs) or a 200 with Accept-Ranges otherwise.
async function serveMedia(req) {
  const url = req.url.split('#')[0];
  const cache = await caches.open(CACHE_VERSION);
  let full = await cache.match(url);
  if (!full) {
    try {
      const net = await fetch(url);            // full file, no Range header
      if (net && net.status === 200) {
        await cache.put(url, net.clone());
        full = net;
      } else {
        return net || fetch(req);              // pass through anything unexpected
      }
    } catch (e) {
      return new Response('', { status: 504, statusText: 'offline' });
    }
  }

  const buf = await full.arrayBuffer();
  const size = buf.byteLength;
  const type = full.headers.get('Content-Type') || 'video/mp4';
  const range = req.headers.get('range');

  if (!range) {
    return new Response(buf, {
      status: 200,
      headers: { 'Content-Type': type, 'Content-Length': String(size), 'Accept-Ranges': 'bytes' },
    });
  }

  const m = /bytes=(\d*)-(\d*)/.exec(range);
  let start, end;
  if (m && m[1] === '' && m[2]) {              // suffix range: last N bytes
    start = Math.max(0, size - parseInt(m[2], 10));
    end = size - 1;
  } else {
    start = m && m[1] ? parseInt(m[1], 10) : 0;
    end = m && m[2] ? parseInt(m[2], 10) : size - 1;
  }
  if (!Number.isFinite(end) || end >= size) end = size - 1;
  if (!Number.isFinite(start) || start > end || start >= size) {
    return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}`, 'Accept-Ranges': 'bytes' } });
  }

  const chunk = buf.slice(start, end + 1);
  return new Response(chunk, {
    status: 206,
    headers: {
      'Content-Type': type,
      'Content-Range': `bytes ${start}-${end}/${size}`,
      'Content-Length': String(chunk.byteLength),
      'Accept-Ranges': 'bytes',
    },
  });
}
