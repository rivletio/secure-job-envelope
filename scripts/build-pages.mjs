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
// Usage: node scripts/build-pages.mjs [outDir]
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(repoRoot, process.argv[2] ?? "_pages");
const siteDist = resolve(repoRoot, "site/dist");
const deskDist = resolve(repoRoot, "dist/client");

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

console.log(`assembled GitHub Pages output at ${out}`);
console.log("  /            demos landing + lifecycle.html + exchange.html");
console.log("  /desk/       desk SPA (index.html <- _shell.html)");
console.log("  /404.html    desk shell (SPA deep-link fallback)");
