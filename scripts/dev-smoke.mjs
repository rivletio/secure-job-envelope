// Smoke-test the DEV server: start it, request the desk, expect a rendered page.
//
// CI builds the production bundles but never ran `vite dev`, so the dev server was
// broken for a long time without anyone noticing (the `@/` path alias did not resolve:
// every request answered 500). Contributors verify UI changes in dev mode; this keeps
// that path alive.
//
// Usage: node scripts/dev-smoke.mjs   (exit 0 = the dev server serves the desk)
import { spawn } from "node:child_process";
import { createServer } from "node:net";

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

const port = await freePort();
const child = spawn("npx", ["vite", "dev", "--port", String(port), "--strictPort", "--host", "127.0.0.1"], {
  stdio: ["ignore", "pipe", "pipe"],
  detached: true, // its own process group, so the whole tree can be stopped
});
let log = "";
child.stdout.on("data", (d) => (log += d));
child.stderr.on("data", (d) => (log += d));
const stop = () => {
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    /* already gone */
  }
};
const fail = (why) => {
  stop();
  console.error(`dev smoke FAILED: ${why}\n--- dev server output ---\n${log.slice(-4000)}`);
  process.exit(1);
};
child.on("exit", (code) => {
  if (code !== null && code !== 0) fail(`the dev server exited with code ${code}`);
});

const deadline = Date.now() + 90_000;
const url = `http://127.0.0.1:${port}/`;
for (;;) {
  if (Date.now() > deadline) fail("the dev server did not answer within 90 s");
  await new Promise((r) => setTimeout(r, 500));
  let res;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  } catch {
    continue; // not listening yet
  }
  const body = await res.text();
  if (res.status !== 200) fail(`GET / answered ${res.status}`);
  if (!body.includes("<html") || !body.includes("</html>")) fail("GET / did not return an HTML document");
  if (/could not be resolved|Cannot find module/.test(log)) fail("the dev server reported unresolved imports");
  break;
}
stop();
console.log(`dev smoke ok: the dev server served the desk on port ${port}`);
process.exit(0);
