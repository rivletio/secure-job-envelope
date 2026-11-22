/* Secure Job Envelope demos — minimal offline service worker.
 *
 * Runtime caching only (stale-while-revalidate); there is no precache manifest, so this
 * file is base-path agnostic and works unchanged whether the site is served from "/" (dev)
 * or "/secure-job-envelope/" (Pages).
 *
 * WHAT THIS WORKER MAY TOUCH — AND THE DESK, WHICH IT MAY NOT
 * The registration scope is the site root, and on Pages the desk SPA is published underneath
 * it (<scope>desk/). A scope is a plain URL prefix: none exists that covers the landing page
 * at <scope> and leaves <scope>desk/ out, so the browser routes desk requests through the
 * fetch handler below. The desk is where a keystore passphrase is typed and secret keys are
 * held in memory. It must always come straight from the network — stale-while-revalidate
 * answers with the old copy first, so a security fix to the desk would land one visit late.
 *
 * The handler therefore answers ONLY for the demo site's own files (isSiteFile, an allowlist —
 * not a "skip the desk" denylist that a renamed or added path could slip past). For anything
 * else it returns before respondWith(): the browser then performs the request exactly as if no
 * worker were installed, and nothing but site files is ever written to the cache. That
 * covers desk/** and 404.html (Pages' deep-link fallback, which is a copy of the desk shell).
 *
 * Adding a demo page: list it in PAGES. scripts/pages-hardening.test.ts fails until every
 * site/*.html is listed, and fails if any desk URL is ever handled.
 *
 * Bump CACHE to invalidate everything on the next activation. v1 cached every same-origin GET
 * under the scope, the desk included; activation deletes it (see below). */
const CACHE = "sje-demos-v2";
/** Every generation's cache starts with this; anything else in the origin is not ours. */
const CACHE_PREFIX = "sje-demos-";

/** The demo site, relative to the registration scope. "" is the landing page itself. */
const PAGES = ["", "index.html", "lifecycle.html", "exchange.html"];
const FILES = ["manifest.webmanifest", "icon.svg"];
/** Vite's hashed bundles: one flat directory, plain file names — nothing nested, no escapes. */
const ASSET = /^assets\/[A-Za-z0-9._-]+$/;

const SCOPE_PATH = new URL(self.registration.scope).pathname;

/** True only for a URL this worker is allowed to answer for and to store. */
function isSiteFile(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.origin !== self.location.origin) return false;
  if (!u.pathname.startsWith(SCOPE_PATH)) return false;
  const rel = u.pathname.slice(SCOPE_PATH.length);
  return PAGES.includes(rel) || FILES.includes(rel) || ASSET.test(rel);
}

self.addEventListener("install", () => {
  // Take over from an earlier generation at once: the point of a new generation may be that
  // the old one must stop (v1 served the desk from its cache).
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Drop the caches of earlier generations whole, noting whether they held anything that
      // is not a site file — i.e. whether an old worker had been serving the desk. Only caches
      // with our prefix: the origin can be shared with other sites (github.io project pages).
      let servedOthers = false;
      for (const name of await caches.keys()) {
        if (!name.startsWith(CACHE_PREFIX) || name === CACHE) continue;
        const old = await caches.open(name);
        if ((await old.keys()).some((req) => !isSiteFile(req.url))) servedOthers = true;
        await caches.delete(name);
      }
      // Belt and braces for the current cache: nothing but site files may stay in it.
      const cache = await caches.open(CACHE);
      for (const req of await cache.keys()) {
        if (isSiteFile(req.url)) continue;
        servedOthers = true;
        await cache.delete(req);
      }

      // Control every open page now, so the old generation stops answering immediately.
      await self.clients.claim();

      // A desk tab opened while an old generation was in charge may be running a copy that
      // came out of the cache just deleted: stale code, on the page where the passphrase is
      // typed, and its lazily loaded chunks are gone. Reload such tabs once so they are
      // rebuilt from the network. Only on a hand-over from a generation that had cached
      // non-site files — at most once per browser, never on an ordinary update.
      //
      // The reloads are started, NOT awaited: navigate() settles only once the page has
      // loaded, the page's request waits for this worker to finish activating, and activation
      // waits for this promise — awaiting it here would deadlock the hand-over.
      if (servedOthers) {
        for (const client of await self.clients.matchAll({ type: "window" })) {
          if (!isSiteFile(client.url)) client.navigate(client.url).catch(() => {});
        }
      }
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  // Not a demo-site file (the desk, 404.html, another origin, anything unknown): return
  // without respondWith() — the network answers, untouched and uncached.
  if (!isSiteFile(req.url)) return;

  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match(req);

      if (cached) {
        // Serve from cache, refresh in the background.
        event.waitUntil(
          fetch(req)
            .then((res) => {
              if (storable(res)) return cache.put(req, res.clone());
            })
            .catch(() => {}),
        );
        return cached;
      }

      try {
        const res = await fetch(req);
        if (storable(res)) cache.put(req, res.clone());
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

/** Only a plain 200-class answer for the URL that was asked for: a redirect could have landed
 *  anywhere (and a stored redirected response cannot answer a navigation anyway). */
function storable(res) {
  return Boolean(res) && res.ok && !res.redirected && res.type !== "opaque";
}
