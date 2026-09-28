// Caches the app shell so it opens offline. API calls always go to the
// network: they're authenticated and must never be served from a cache.
const CACHE = "flow-remote-v11";
const SHELL = [
  "./", "./index.html", "./app.css", "./manifest.webmanifest", "./icon.svg", "./icon-192.png",
  "./js/app.js", "./js/api.js", "./js/db.js", "./js/fuzzy.js", "./js/envelope.js", "./js/pairing.js",
  "./vendor/jsqr-1.4.0/jsQR.js", "./vendor/qrcode-generator-2.0.4/qrcode.mjs",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || e.request.method !== "GET") return;
  if (url.pathname.startsWith("/v1/")) return;
  // Network first, so a deploy shows up on the next open; cache when offline.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok) {
          const copy = res.clone(); // clone now; the page will read res
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request).then((r) => r || caches.match("./index.html"))),
  );
});
