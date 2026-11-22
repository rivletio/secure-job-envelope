// @ts-check
// Assemble the GitHub Pages publish directory from the two already-built outputs:
//   - the static demo site  (site/dist, built with base /secure-job-envelope/)
//   - the static desk SPA    (dist/client, built with base /secure-job-envelope/desk/)
//
// Layout produced in <out> (default ./_pages):
//   /                      the demos landing + lifecycle.html + exchange.html (+ PWA assets)
//   /desk/                 the desk SPA shell (index.html = the prerendered _shell.html)
//   /404.html              the desk shell, so deep-link reloads under /desk/* boot the SPA
//                          (GitHub Pages serves the site-root 404.html for any miss, and the
//                           browser URL is preserved, so the client router resolves the route)
//
// Then harden and verify it. Pages cannot send response headers, so every HTML document gets
// its Content-Security-Policy as a <meta> element (scripts/pages-csp.mjs has the policy and
// the reasoning; inline scripts are allowed by SHA-256 hash, computed here from the built
// file). The build FAILS — nothing is left to publish — if any emitted document lacks its
// policy, holds an inline script, style or event handler the policy would refuse, loads
// anything from another origin, or points at a file that is not in the output.
//
// Usage: node scripts/build-pages.mjs [outDir]
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  auditDocument,
  cssUrls,
  externalRefsInCss,
  hardenDocument,
  localRefsInHtml,
  parsePolicy,
  scanHtml,
} from "./pages-csp.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(repoRoot, process.argv[2] ?? "_pages");
const siteDist = resolve(repoRoot, "site/dist");
const deskDist = resolve(repoRoot, "dist/client");
// The path the site is published under — the same default as site/vite.config.ts. The desk
// is published at <base>desk/ (vite.config.ts: DESK_BASE).
const base = process.env.SITE_BASE ?? "/secure-job-envelope/";

for (const [label, path] of [
  ["demo site (run `npm run site:build`)", siteDist],
  ["desk SPA (run `npm run desk:build`)", deskDist],
]) {
  if (!existsSync(path)) {
    console.error(`missing build output for ${label}: ${path}`);
    process.exit(1);
  }
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// Demos + landing at the site root.
cpSync(siteDist, out, { recursive: true });
// Desk SPA under /desk/.
cpSync(deskDist, resolve(out, "desk"), { recursive: true });

const shell = resolve(out, "desk/_shell.html");
if (!existsSync(shell)) {
  console.error(`desk SPA shell not found: ${shell} (is spa mode enabled in the desk build?)`);
  process.exit(1);
}
// The desk's clean entry, and the site-wide SPA fallback for deep links.
cpSync(shell, resolve(out, "desk/index.html"));
cpSync(shell, resolve(out, "404.html"));

// ── Harden: the policy goes into every HTML document ────────────────────────────────────
/** Every file under `dir`, as "/"-separated paths relative to it. */
function walk(/** @type {string} */ dir, prefix = "") {
  /** @type {string[]} */
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = `${prefix}${entry.name}`;
    if (entry.isDirectory()) files.push(...walk(resolve(dir, entry.name), `${rel}/`));
    else files.push(rel);
  }
  return files.sort();
}
const read = (/** @type {string} */ rel) => readFileSync(resolve(out, rel), "utf8");
/** The desk shell is published under desk/ and, as the deep-link fallback, as 404.html. */
const kindOf = (/** @type {string} */ rel) =>
  rel === "404.html" || rel.startsWith("desk/") ? "desk" : "site";

const published = walk(out);
const documents = published.filter((rel) => rel.endsWith(".html"));
for (const rel of documents) {
  writeFileSync(resolve(out, rel), hardenDocument(read(rel), kindOf(rel)));
}

// ── Verify what is about to be published ────────────────────────────────────────────────
/** @type {string[]} */
const problems = [];

/** A same-origin reference must stay inside the published site and name a file that exists. */
function checkLocalRef(/** @type {string} */ from, /** @type {string} */ ref) {
  const origin = "https://pages.invalid";
  const url = new URL(ref, `${origin}${base}${from}`);
  if (!url.pathname.startsWith(base)) {
    problems.push(`${from}: ${ref} points outside the published site (${base})`);
    return;
  }
  let target = decodeURIComponent(url.pathname.slice(base.length));
  if (target === "" || target.endsWith("/")) target += "index.html";
  if (!published.includes(target)) {
    problems.push(`${from}: ${ref} does not exist in the output (looked for ${target})`);
  }
}

for (const rel of published) {
  if (rel.endsWith(".html")) {
    const html = read(rel);
    for (const problem of auditDocument(html, kindOf(rel))) problems.push(`${rel}: ${problem}`);
    for (const ref of localRefsInHtml(html)) checkLocalRef(rel, ref);
  } else if (rel.endsWith(".css")) {
    const css = read(rel);
    const external = new Set(externalRefsInCss(css));
    for (const url of external) {
      problems.push(`${rel}: url(${url}) is not a same-origin relative reference`);
    }
    for (const url of cssUrls(css)) if (!external.has(url)) checkLocalRef(rel, url);
  } else if (rel.endsWith(".webmanifest")) {
    if (/:\/\//.test(read(rel))) problems.push(`${rel}: references an absolute URL`);
  } else if (rel.endsWith(".svg")) {
    // An SVG opened on its own is a document too, and it cannot carry the <meta> policy:
    // the only safe SVG to publish is an inert one.
    if (/<script|\son[a-z]+\s*=|javascript:|<foreignObject/i.test(read(rel))) {
      problems.push(`${rel}: an SVG must not carry script, event handlers or foreign content`);
    }
  } else if (rel.endsWith(".js")) {
    // A tripwire, not a proof: what a script does at run time cannot be read off its text.
    // But the two dependencies known to append an inline <style> (sonner, and
    // react-style-singleton under Radix Dialog) both carry this old-IE idiom, and
    // scripts/vite-plugin-no-inline-styles.ts keeps both out of the bundle. If either is back,
    // style-src 'self' would refuse it in the browser: unstyled toasts, no scroll lock, and
    // a violation on every load.
    if (/\bstyleSheet\.cssText\s*=/.test(read(rel))) {
      problems.push(
        `${rel}: holds a run-time <style> injector (…styleSheet.cssText = …), which ` +
          `style-src 'self' refuses — see scripts/vite-plugin-no-inline-styles.ts`,
      );
    }
  }
}

if (problems.length > 0) {
  console.error(`refusing to publish ${out}: ${problems.length} problem(s)`);
  for (const problem of problems) console.error(`  ✗ ${problem}`);
  // Leave nothing behind that a later step could upload.
  rmSync(out, { recursive: true, force: true });
  process.exit(1);
}

console.log(`assembled GitHub Pages output at ${out}`);
console.log("  /            demos landing + lifecycle.html + exchange.html");
console.log("  /desk/       desk SPA (index.html <- _shell.html)");
console.log("  /404.html    desk shell (SPA deep-link fallback)");
console.log(`hardened ${documents.length} HTML documents with a Content-Security-Policy <meta>:`);
for (const rel of documents) {
  const meta = scanHtml(read(rel)).find((el) => el.attrs["http-equiv"] !== undefined);
  const policy = meta?.attrs["content"] ?? "";
  const hashes = (parsePolicy(policy).get("script-src") ?? []).filter((s) => s !== "'self'");
  console.log(`  ${rel} (${kindOf(rel)}; ${hashes.length} inline script hash(es))`);
  console.log(`    ${policy}`);
}
