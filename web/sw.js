// Caches the app shell so it opens offline. API calls always go to the
// network: they're authenticated and must never be served from a cache.
const CACHE = "flow-remote-v38"; // keep in step with BUILD in js/app.js
const SHELL = [
  "./", "./index.html", "./app.css", "./manifest.webmanifest", "./icon.svg", "./icon-192.png", "./flow-wave.svg",
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
  // Cache first. The app must open at once even when the Mac is asleep or
  // the phone is off the tailnet, and a request to an unreachable Mac can
  // hang rather than fail. Every page is the one-page app, whatever the
  // path. A new build still arrives: the browser fetches sw.js itself on
  // each open, and a changed one caches the new files and takes over.
  const key = e.request.mode === "navigate" ? "./" : e.request;
  e.respondWith(
    caches.match(key, { ignoreSearch: true }).then((hit) => hit || fetch(e.request).then((res) => {
      if (res.ok) {
        const copy = res.clone(); // clone now; the page will read res
        caches.open(CACHE).then((c) => c.put(e.request, copy));
      }
      return res;
    })).catch(() => caches.match("./")),
  );
});
