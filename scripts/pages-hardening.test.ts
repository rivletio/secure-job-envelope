/** Regression tests for the hardening of the published site (GitHub Pages):
 *
 *   - nothing shipped loads from a third-party origin (the desk once linked a Google Fonts
 *     stylesheet on the page where the keystore passphrase is typed);
 *   - every shipped HTML document carries the Content-Security-Policy, early enough to govern
 *     everything it loads, and the policy stays as tight as it is;
 *   - the demo site's service worker never answers for, or stores, a desk URL;
 *   - the demo site's DOM helper has no way to take markup.
 *
 *  These run on sources. The built output is checked by scripts/build-pages.mjs itself, with
 *  the same functions, and that build fails on any finding (CI runs it on every pull request).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";
import vm from "node:vm";
import {
  auditDocument,
  auditPolicy,
  buildPolicy,
  externalRefsInCss,
  externalRefsInHtml,
  hardenDocument,
  parsePolicy,
  scanHtml,
  scriptHash,
} from "./pages-csp.mjs";

const root = new URL("../", import.meta.url);
const read = (rel: string) => readFileSync(new URL(rel, root), "utf8");

/** Files under `dir` (repo-relative, "/"-separated), recursively. */
function walk(dir: string): string[] {
  return readdirSync(new URL(`${dir}/`, root), { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(`${dir}/${entry.name}`) : [`${dir}/${entry.name}`],
  );
}

const sitePages = readdirSync(new URL("site/", root)).filter((name) => name.endsWith(".html"));
/** Browser code that ends up on Pages: the demo site and the desk (tests excluded). */
const shippedCode = [...walk("site/src"), ...walk("src")].filter(
  (file) => /\.(ts|tsx)$/.test(file) && !/\.test\.ts$/.test(file),
);

// ── The policy ──────────────────────────────────────────────────────────────────────────

describe("Content-Security-Policy of the published pages", () => {
  // Golden strings on purpose: loosening the policy must be a visible, deliberate edit here.
  it("is exactly this for the demo site", () => {
    assert.equal(
      buildPolicy("site"),
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
        "connect-src 'none'; manifest-src 'self'; worker-src 'self'; " +
        "base-uri 'none'; form-action 'none'; object-src 'none'",
    );
  });

  it("is exactly this for the desk, plus one hash per inline script", () => {
    assert.equal(
      buildPolicy("desk", ["'sha256-AAAA'", "'sha256-BBBB'", "'sha256-AAAA'"]),
      "default-src 'none'; script-src 'self' 'sha256-AAAA' 'sha256-BBBB'; style-src 'self'; " +
        "img-src 'self'; font-src 'self'; connect-src 'none'; " +
        "base-uri 'none'; form-action 'none'; object-src 'none'",
    );
  });

  it("allows this origin, nothing, or a hash — and carries nothing a <meta> ignores", () => {
    for (const kind of ["site", "desk"] as const) {
      const policy = buildPolicy(kind, [scriptHash("x")]);
      assert.deepEqual(auditPolicy(policy), []);
      for (const sources of parsePolicy(policy).values()) {
        for (const source of sources) {
          assert.match(source, /^'(self|none|sha256-[A-Za-z0-9+/]+=*)'$/);
        }
      }
    }
  });

  it("is rejected once it is loosened", () => {
    const strict = buildPolicy("desk");
    const loosened = [
      strict.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"),
      strict.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'"),
      strict.replace("script-src 'self'", "script-src 'self' https://cdn.example"),
      strict.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'"),
      strict.replace("style-src 'self'", "style-src 'self' https://fonts.googleapis.com"),
      strict.replace("font-src 'self'", "font-src https://fonts.gstatic.com"),
      strict.replace("img-src 'self'", "img-src *"),
      strict.replace("default-src 'none'", "default-src 'self'"),
      strict.replace("base-uri 'none'", "base-uri 'self'"),
      strict.replace("; form-action 'none'", ""),
      `${strict}; frame-ancestors 'none'`,
      `${strict}; report-uri /csp`,
      `${strict}; sandbox allow-scripts`,
    ];
    for (const policy of loosened) {
      assert.notEqual(policy, strict);
      assert.notDeepEqual(auditPolicy(policy), [], policy);
    }
  });

  it("hashes an inline script the way the browser does", () => {
    const text = 'self.x = 1;\nconsole.log("é")';
    const expected = `'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`;
    assert.equal(scriptHash(text), expected);
    // The HTML parser turns CRLF and lone CR into LF before a script's text exists.
    assert.equal(scriptHash(text.replace("\n", "\r\n")), expected);
    assert.equal(scriptHash(text.replace("\n", "\r")), expected);
  });
});

// ── Documents ───────────────────────────────────────────────────────────────────────────

/** The shape of the desk shell TanStack Start prerenders: inline bootstrap scripts included. */
const SHELL =
  '<!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/>' +
  '<meta name="viewport" content="width=device-width, initial-scale=1"/>' +
  '<link rel="stylesheet" href="/secure-job-envelope/desk/assets/styles-abc.css"/>' +
  "<title>SJE</title></head><body><!--$--><!--/$-->" +
  '<script data-tsr="">self.$_TSR={u:1795322765346};if(1<2){document.title="a</b>"}</script>' +
  '<script type="module" async="" src="/secure-job-envelope/desk/assets/index-abc.js"></script>' +
  "<script>document.currentScript.remove()</script></body></html>";

describe("a shipped HTML document", () => {
  const hardened = hardenDocument(SHELL, "desk");

  it("gets the policy as the first thing in <head> after the charset", () => {
    assert.deepEqual(auditDocument(hardened, "desk"), []);
    const names = scanHtml(hardened).map((el) => el.name);
    assert.deepEqual(names.slice(0, 4), ["html", "head", "meta", "meta"]);
    const [charset, policy] = scanHtml(hardened).slice(2);
    assert.ok(charset && "charset" in charset.attrs);
    assert.equal(policy?.attrs["http-equiv"], "Content-Security-Policy");
    // Without a leading charset the policy comes first of all.
    const bare = hardenDocument("<html><head><title>t</title></head><body></body></html>", "site");
    assert.equal(scanHtml(bare)[2]?.attrs["http-equiv"], "Content-Security-Policy");
    assert.deepEqual(auditDocument(bare, "site"), []);
  });

  it("lists the hash of each of its inline scripts, and of nothing else", () => {
    const policy = scanHtml(hardened).find((el) => el.attrs["http-equiv"])?.attrs["content"] ?? "";
    const expected = [
      'self.$_TSR={u:1795322765346};if(1<2){document.title="a</b>"}',
      "document.currentScript.remove()",
    ].map((text) => `'sha256-${createHash("sha256").update(text).digest("base64")}'`);
    assert.deepEqual(parsePolicy(policy).get("script-src"), ["'self'", ...expected]);
  });

  it("is refused without the policy", () => {
    assert.match(auditDocument(SHELL, "desk").join("\n"), /no <meta http-equiv/);
  });

  it("is refused when anything changes after the policy was written", () => {
    const tampered: [string, RegExp][] = [
      // an inline script the policy has no hash for
      [
        hardened.replace("</body>", "<script>alert(1)</script></body>"),
        /inline script is not allowed/,
      ],
      // an inline script whose text changed (a new build timestamp, say)
      [hardened.replace("1795322765346", "1795322765347"), /inline script is not allowed/],
      // something loading before the policy can govern it
      [hardened.replace("<head>", '<head><script src="/x.js"></script>'), /before the policy/],
      [
        hardened.replace("<head>", '<head><link rel="stylesheet" href="/x.css">'),
        /before the policy/,
      ],
      // a second policy element
      [
        hardened.replace(
          "</head>",
          '<meta http-equiv="content-security-policy" content="x"></head>',
        ),
        /2 policy <meta>/,
      ],
      // what the policy refuses at run time
      [hardened.replace("<body>", '<body style="margin:0">'), /inline styles are refused/],
      [hardened.replace("<body>", "<body><style>p{}</style>"), /inline <style> element is refused/],
      [hardened.replace("<body>", '<body onload="x()">'), /inline event handlers are refused/],
      [hardened.replace("<body>", '<body><a href="javascript:x()">y</a>'), /javascript:/],
      [hardened.replace("</title>", '</title><base href="/elsewhere/">'), /<base> is refused/],
      // another origin
      [
        hardened.replace(
          "</title>",
          '</title><link rel="preconnect" href="https://fonts.gstatic.com">',
        ),
        /not a same-origin/,
      ],
      [
        hardened.replace(
          "</title>",
          '</title><link rel="stylesheet" href="//fonts.googleapis.com/css2">',
        ),
        /not a same-origin/,
      ],
      [
        hardened.replace("<body>", '<body><img src="https://example.com/p.gif">'),
        /not a same-origin/,
      ],
    ];
    for (const [html, problem] of tampered) {
      assert.notEqual(html, hardened);
      assert.match(auditDocument(html, "desk").join("\n"), problem);
    }
  });

  it("is refused when it carries the other app's policy, or a weaker one", () => {
    assert.match(auditDocument(hardened, "site").join("\n"), /is not the site policy/);
    const weaker = hardened.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'");
    assert.match(auditDocument(weaker, "desk").join("\n"), /style-src allows 'unsafe-inline'/);
  });

  it("may link anywhere, but loads only from its own origin", () => {
    const html =
      '<a href="https://github.com/example/repo">source</a><svg xmlns="http://www.w3.org/2000/svg"/>' +
      '<link rel="icon" href="/icon.svg"><img src="a.png" srcset="b.png 2x, https://x.example/c.png 3x">' +
      '<script src="//cdn.example/x.js"></script><form action="https://x.example/post"></form>' +
      '<!-- <script src="https://commented.example/x.js"></script> -->';
    assert.deepEqual(externalRefsInHtml(html), [
      '<img srcset="https://x.example/c.png">',
      '<script src="//cdn.example/x.js">',
      '<form action="https://x.example/post">',
    ]);
  });
});

// ── Sources: no third-party origin ──────────────────────────────────────────────────────

describe("the sources of the published pages", () => {
  it("demo site templates pass the site policy as written", () => {
    assert.ok(sitePages.length >= 3);
    for (const page of sitePages) {
      // Hardened as the Pages build will harden them: no inline script, style or handler,
      // and nothing loaded from another origin.
      const problems = auditDocument(hardenDocument(read(`site/${page}`), "site"), "site");
      assert.deepEqual(problems, [], `site/${page}`);
    }
  });

  it("stylesheets import and load nothing from another origin", () => {
    const sheets = [...walk("src"), ...walk("site/src")].filter((f) => f.endsWith(".css"));
    assert.ok(sheets.includes("src/styles.css") && sheets.includes("site/src/style.css"));
    for (const file of sheets) assert.deepEqual(externalRefsInCss(read(file)), [], file);
    assert.deepEqual(
      externalRefsInCss('@import url("https://fonts.googleapis.com/css2?family=X");'),
      ["https://fonts.googleapis.com/css2?family=X"],
    );
    assert.deepEqual(
      externalRefsInCss("a{background:url(//x.example/a.png)} /* url(https://ok) */"),
      ["//x.example/a.png"],
    );
  });

  it("the desk defines no document link, script or media element with an absolute URL", () => {
    // Head entries are objects ({ rel, href } / { src }); elements are JSX. A plain <a href>
    // to another site is navigation, and stays allowed.
    const headEntry = /\b(?:href|src)\s*:\s*["'`]\s*(?:[a-z][a-z0-9+.-]*:)?\/\//i;
    const element =
      /<(?:link|script|img|iframe|source|video|audio|embed|object|image|use)\b[^>]*["'`{]\s*(?:[a-z][a-z0-9+.-]*:)?\/\//i;
    for (const file of shippedCode) {
      const code = read(file);
      assert.doesNotMatch(code, headEntry, file);
      assert.doesNotMatch(code, element, file);
    }
    // The patterns do catch what the desk used to ship.
    assert.match('{ rel: "preconnect", href: "https://fonts.googleapis.com" }', headEntry);
    assert.match('<link rel="stylesheet" href="https://fonts.googleapis.com/css2" />', element);
  });

  it("the service worker and the manifest name no other origin", () => {
    for (const file of walk("site/public").filter((f) => !f.endsWith(".svg"))) {
      assert.doesNotMatch(read(file), /:\/\/|importScripts/, file);
    }
  });
});

// ── The demo site's DOM helper ──────────────────────────────────────────────────────────

describe("markup sinks", () => {
  const SINK =
    /\b(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|createContextualFragment|parseFromString|srcdoc|setHTMLUnsafe)\b|document\.write/;

  it("the demo site's helpers build DOM from nodes and text, never from markup", () => {
    const files = walk("site/src").filter((f) => f.endsWith(".ts"));
    assert.ok(files.includes("site/src/ui.ts"));
    for (const file of files) {
      // Comments may name a sink (to say it is banned); code may not use one.
      const code = read(file)
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      assert.doesNotMatch(code, SINK, file);
    }
    // el() special-cases exactly one attribute, and it is not a markup one.
    const el = /export function el\b[\s\S]*?\n}\n/.exec(read("site/src/ui.ts"))?.[0] ?? "";
    assert.deepEqual(el.match(/k === "[^"]*"/g), ['k === "class"']);
  });

  it("the desk has none either", () => {
    for (const file of shippedCode.filter((f) => f.startsWith("src/"))) {
      assert.doesNotMatch(read(file), SINK, file);
    }
  });
});

// ── The demo site's service worker ──────────────────────────────────────────────────────

type Listener = (event: Record<string, unknown>) => void;
type FakeClient = { url: string; navigate: (to: string) => Promise<void> };

/** Run site/public/sw.js in a fake worker global, with recording stand-ins for the platform. */
function loadWorker(scope: string, caches0: Record<string, string[]> = {}, windows: string[] = []) {
  const listeners = new Map<string, Listener>();
  const stores = new Map(
    Object.entries(caches0).map(([name, urls]) => [name, new Map(urls.map((url) => [url, {}]))]),
  );
  const seen = { fetched: [] as string[], opened: [] as string[], reloaded: [] as string[] };
  const calls = { skipWaiting: 0, claim: 0 };
  const urlOf = (req: string | { url: string }) => (typeof req === "string" ? req : req.url);
  const caches = {
    keys: async () => [...stores.keys()],
    delete: async (name: string) => stores.delete(name),
    open: async (name: string) => {
      seen.opened.push(name);
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name)!;
      return {
        keys: async () => [...store.keys()].map((url) => ({ url })),
        match: async (req: string | { url: string }) => store.get(urlOf(req)),
        put: async (req: { url: string }, res: object) => void store.set(req.url, res),
        delete: async (req: { url: string }) => store.delete(req.url),
      };
    },
  };
  const self = {
    location: { origin: new URL(scope).origin },
    registration: { scope },
    addEventListener: (type: string, listener: Listener) => void listeners.set(type, listener),
    skipWaiting: () => void (calls.skipWaiting += 1),
    clients: {
      claim: async () => void (calls.claim += 1),
      matchAll: async (): Promise<FakeClient[]> =>
        windows.map((url) => ({
          url,
          // As in a browser: this settles only once the reloaded page has loaded — and a page
          // in scope cannot load before the worker has finished activating.
          navigate: (to) => {
            seen.reloaded.push(to);
            return new Promise<void>(() => {});
          },
        })),
    },
  };
  const fetch = async (req: { url: string }) => {
    seen.fetched.push(req.url);
    return { ok: true, redirected: false, type: "basic", clone: () => ({}) };
  };
  vm.runInContext(read("site/public/sw.js"), vm.createContext({ self, caches, fetch, URL }));

  return {
    stores,
    seen,
    calls,
    install: () => listeners.get("install")!({}),
    async activate() {
      let done: unknown;
      listeners.get("activate")!({ waitUntil: (p: unknown) => void (done = p) });
      let timer: NodeJS.Timeout | undefined;
      const activated = await Promise.race([
        Promise.resolve(done).then(() => true),
        new Promise<boolean>((resolve) => (timer = setTimeout(() => resolve(false), 2000))),
      ]);
      clearTimeout(timer);
      assert.ok(activated, "activation must not wait on the pages it reloads: that deadlocks");
    },
    /** Dispatch a fetch event; resolves to whether the worker chose to answer it. */
    async fetch(url: string, init: { method?: string; mode?: string } = {}) {
      const waits: unknown[] = [];
      let answer: unknown;
      listeners.get("fetch")!({
        request: { url, method: init.method ?? "GET", mode: init.mode ?? "no-cors" },
        respondWith: (p: unknown) => void (answer = p),
        waitUntil: (p: unknown) => void waits.push(p),
      });
      await Promise.all([answer, ...waits]);
      return answer !== undefined;
    },
  };
}

describe("the demo site's service worker", () => {
  const PAGES = "https://owner.example/secure-job-envelope/";
  const DEV = "http://localhost:5173/";
  const deskUrls = (scope: string) =>
    [
      "desk/",
      "desk",
      "desk/index.html",
      "desk/_shell.html",
      "desk/keys",
      "desk/t/tvl_abc123def",
      "desk/assets/index-CMB8KwEl.js",
      "desk/assets/styles-CFwjat0t.css",
      "desk/assets/fraunces-latin-opsz-normal-DihXLNYH.woff2",
      "desk/favicon.svg",
      "desk/schemas/traveler-0.1.0.json",
      "desk/?source=pwa",
      // Pages' deep-link fallback is a copy of the desk shell.
      "404.html",
      // …and so is the answer to any path that does not exist.
      "no-such-page",
      // spellings that try to pass for a site file
      "assets/../desk/index.html",
      "assets/%2e%2e/desk/assets/index-CMB8KwEl.js",
      "assets/..%2fdesk%2findex.html",
      "assets/x/../../desk/",
      "index.html/../desk/",
      "/desk/",
      "DESK/",
    ].map((path) => scope + path);

  for (const scope of [PAGES, DEV]) {
    it(`leaves every desk URL to the network (scope ${new URL(scope).pathname})`, async () => {
      const worker = loadWorker(scope);
      for (const url of deskUrls(scope)) {
        for (const mode of ["navigate", "no-cors", "cors"]) {
          assert.equal(await worker.fetch(url, { mode }), false, `${mode} ${url}`);
        }
      }
      // Not answered, not fetched on the page's behalf, and no cache was even opened.
      assert.deepEqual(worker.seen, { fetched: [], opened: [], reloaded: [] });
    });

    it(`answers for the demo site's own files (scope ${new URL(scope).pathname})`, async () => {
      const worker = loadWorker(scope);
      const own = [
        "",
        ...sitePages,
        ...readdirSync(new URL("site/public/", root)).filter((name) => name !== "sw.js"),
        "assets/main-CoOAP_or.js",
        "assets/ui-D6NYXBuN.css",
        "lifecycle.html?step=2",
      ];
      for (const path of own) assert.equal(await worker.fetch(scope + path), true, path);
      const stored = [...worker.stores.get("sje-demos-v2")!.keys()];
      assert.deepEqual(stored.sort(), own.map((path) => scope + path).sort());
    });
  }

  it("ignores other origins and anything but GET", async () => {
    const worker = loadWorker(PAGES);
    assert.equal(await worker.fetch("https://fonts.googleapis.com/css2?family=Archivo"), false);
    assert.equal(await worker.fetch("https://owner.example/another-project/index.html"), false);
    assert.equal(await worker.fetch(`${PAGES}index.html`, { method: "POST" }), false);
    assert.deepEqual(worker.seen.fetched, []);
  });

  it("has no precache: installing and activating fetches and stores nothing", async () => {
    const worker = loadWorker(PAGES);
    worker.install();
    await worker.activate();
    assert.deepEqual(worker.seen.fetched, []);
    assert.deepEqual([...worker.stores.get("sje-demos-v2")!.keys()], []);
    assert.doesNotMatch(read("site/public/sw.js"), /\.addAll\(|\.add\(/);
  });

  it("takes over from the generation that cached the desk, and stops it at once", async () => {
    // v1 stored every same-origin GET under the scope — desk included.
    const v1 = ["", "assets/main-CoOAP_or.js", "desk/", "desk/assets/index-n79i6jnI.js"];
    const worker = loadWorker(
      PAGES,
      { "sje-demos-v1": v1.map((path) => PAGES + path), "another-app-cache": [`${PAGES}desk/`] },
      [`${PAGES}desk/keys`, `${PAGES}lifecycle.html`],
    );
    worker.install();
    assert.equal(worker.calls.skipWaiting, 1, "must not wait for old tabs to close");
    await worker.activate();
    assert.equal(worker.calls.claim, 1, "must take control of open pages");
    // Its own old cache is gone; a cache it does not own (the origin may be shared) is not.
    assert.deepEqual([...worker.stores.keys()].sort(), ["another-app-cache", "sje-demos-v2"]);
    // A desk tab the old generation may have served from cache is rebuilt from the network;
    // a demo page is left alone.
    assert.deepEqual(worker.seen.reloaded, [`${PAGES}desk/keys`]);
    assert.equal(await worker.fetch(`${PAGES}desk/`, { mode: "navigate" }), false);
  });

  it("scrubs anything that is not a site file out of its own cache", async () => {
    const worker = loadWorker(PAGES, {
      "sje-demos-v2": [`${PAGES}index.html`, `${PAGES}desk/`, `${PAGES}404.html`],
    });
    await worker.activate();
    assert.deepEqual([...worker.stores.get("sje-demos-v2")!.keys()], [`${PAGES}index.html`]);
  });

  it("reloads nothing on an ordinary update", async () => {
    const worker = loadWorker(
      PAGES,
      { "sje-demos-v1": [PAGES, `${PAGES}assets/ui-D6NYXBuN.css`] },
      [`${PAGES}desk/`, PAGES],
    );
    await worker.activate();
    assert.deepEqual([...worker.stores.keys()], ["sje-demos-v2"]);
    assert.deepEqual(worker.seen.reloaded, []);
  });
});
