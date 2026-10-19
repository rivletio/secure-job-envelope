/* Secure Job Envelope demos — minimal offline service worker.
 *
 * Runtime caching only (stale-while-revalidate for same-origin GETs); there is
 * no precache manifest, so this file is base-path agnostic and works unchanged
 * whether the site is served from "/" (dev) or "/secure-job-envelope/" (Pages).
 * Bump CACHE to invalidate everything on the next activation. */
const CACHE = "sje-demos-v1";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  if (new URL(req.url).origin !== self.location.origin) return;

  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match(req);

      if (cached) {
        // Serve from cache, refresh in the background.
        event.waitUntil(
          fetch(req)
            .then((res) => {
              if (res && res.ok) return cache.put(req, res.clone());
            })
            .catch(() => {}),
        );
        return cached;
      }

      try {
        const res = await fetch(req);
        if (res && res.ok && res.type !== "opaque") cache.put(req, res.clone());
        return res;
      } catch (err) {
        // Offline and never cached: fall back to the app shell for navigations.
        if (req.mode === "navigate") {
          const shell =
            (await cache.match(self.registration.scope)) ||
            (await cache.match(new URL("index.html", self.registration.scope).href));
          if (shell) return shell;
        }
        throw err;
      }
    })(),
  );
});
