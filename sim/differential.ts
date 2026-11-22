/** Cross-implementation differential fuzzer.
 *
 *  For each seed it builds one case — a valid traveler, usually with one to three
 *  adversarial mutations stacked on it, rendered to exact wire BYTES (case.ts) — and
 *  asks BOTH implementations for their verdict (parse / hash / level / bound) on
 *  those bytes. Any disagreement is a break: the two codebases are supposed to be
 *  interchangeable, so a document one accepts and the other refuses — or that they
 *  hash differently — undermines the whole content-addressing premise. A crash, a
 *  non-answer, a hang or a slow answer from either side is reported the same way.
 *
 *  It never stops at the first finding. Every seed runs; the findings are then
 *  grouped by the mutation responsible — for a stacked case, the smallest subset of
 *  its mutations that still reproduces — so one root cause reads as one line.
 *
 *  Deterministic in the seed range, so every failure reproduces exactly from the seed
 *  it printed. Exits 1 if anything was found, so CI fails loudly.
 *
 *  Run: node --experimental-strip-types sim/differential.ts [options]
 *    --seeds N        how many seeds (default 20000)        --start S   first seed (default 1)
 *    --jobs J         worker processes (default: one per core, at most 8)
 *    --bin PATH       the Rust `envelope` binary (default: this checkout's release build)
 *    --ts-root DIR    use the TypeScript reference of another checkout (see sim/README.md)
 *    --only a,b       apply exactly these mutations to every seed instead of drawing
 *    --save DIR       write each finding's bytes (<seed>.bin) and verdicts (<seed>.verdicts.json)
 *    --report FILE    write the full result as JSON
 *    --replay PATH    judge a saved file (or every file in a directory) instead of seeds
 *    --quiet          summary and grouped table only, no per-finding detail
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCase, CATALOG, mutationNamed, type Case } from "./case.ts";
import {
  REJECT,
  diffVerdicts,
  findingsOf,
  loadTsImpl,
  rustOutcome,
  tsOutcome,
  type Outcome,
  type TsImpl,
} from "./verdict.ts";

/** A worker that reports no progress for this long is stuck inside the TypeScript
 *  reference (the Rust CLI has its own, shorter, timeout). It is killed, the seed it
 *  was on is recorded as a finding, and the rest of its seeds run without that one. */
const HANG_MS = 30_000;
const MAX_HANGS_PER_WORKER = 8;

type Args = {
  seeds: number;
  start: number;
  jobs: number;
  bin: string;
  tsRoot?: string;
  only?: string[];
  save?: string;
  report?: string;
  replay?: string;
  quiet: boolean;
  // Set by the parent on its workers: handle every `of`-th seed from offset `index`,
  // leave out `skip`, write the result to `result` and progress to `heartbeat`.
  stripe?: { index: number; of: number };
  skip: number[];
  result?: string;
  heartbeat?: string;
};

function parseArgs(argv: string[]): Args {
  const a: Args = {
    seeds: 20_000,
    start: 1,
    jobs: Math.min(8, availableParallelism()),
    bin: "crates/secure-job-envelope/target/release/envelope",
    quiet: false,
    skip: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    const next = () => {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${v} needs a value`);
      return value;
    };
    if (v === "--seeds") a.seeds = Number(next());
    else if (v === "--start") a.start = Number(next());
    else if (v === "--jobs") a.jobs = Math.max(1, Number(next()));
    else if (v === "--bin") a.bin = next();
    else if (v === "--ts-root") a.tsRoot = next();
    else if (v === "--only") a.only = next().split(",");
    else if (v === "--save") a.save = next();
    else if (v === "--report") a.report = next();
    else if (v === "--replay") a.replay = next();
    else if (v === "--quiet") a.quiet = true;
    else if (v === "--stripe") {
      const [index, of] = next().split("/").map(Number);
      a.stripe = { index: index!, of: of! };
    } else if (v === "--skip") a.skip = next().split(",").map(Number);
    else if (v === "--result") a.result = next();
    else if (v === "--heartbeat") a.heartbeat = next();
    else throw new Error(`unknown option ${v}`);
  }
  if (!Number.isInteger(a.seeds) || a.seeds < 0 || !Number.isInteger(a.start)) throw new Error("--seeds / --start must be integers");
  for (const name of a.only ?? []) mutationNamed(name);
  return a;
}

/* ---------------- results ---------------- */

type Finding = {
  seed: number;
  /** Every mutation in the case, with the variant each chose. */
  label: string;
  /** The smallest subset of them that still reproduces (names only). */
  culprit: string;
  /** What is wrong, as groupable strings (see `findingsOf`). */
  kinds: string[];
  /** The verdict fields that differ, with their values. */
  diffs: string[];
  ts: Outcome;
  rust: Outcome;
  bytes: number;
  /** The first bytes of the document, made printable. */
  head: string;
};

type Tally = { cases: number; alone: number; findings: number };
type Slowest = { ms: number; seed: number; label: string };

type Result = {
  checked: number;
  unmutated: number;
  single: number;
  bothAccept: number;
  bothRefuse: number;
  findings: Finding[];
  /** Per mutation: cases it bit in, cases it was the only one, findings it is responsible for. */
  mutations: Record<string, Tally>;
  slowest: { ts: Slowest; rust: Slowest };
};

const emptyResult = (): Result => ({
  checked: 0,
  unmutated: 0,
  single: 0,
  bothAccept: 0,
  bothRefuse: 0,
  findings: [],
  mutations: {},
  slowest: { ts: { ms: 0, seed: 0, label: "" }, rust: { ms: 0, seed: 0, label: "" } },
});

const tallyOf = (result: Result, name: string): Tally => (result.mutations[name] ??= { cases: 0, alone: 0, findings: 0 });

function merge(into: Result, part: Result): void {
  into.checked += part.checked;
  into.unmutated += part.unmutated;
  into.single += part.single;
  into.bothAccept += part.bothAccept;
  into.bothRefuse += part.bothRefuse;
  into.findings.push(...part.findings);
  for (const [name, t] of Object.entries(part.mutations)) {
    const mine = tallyOf(into, name);
    mine.cases += t.cases;
    mine.alone += t.alone;
    mine.findings += t.findings;
  }
  for (const side of ["ts", "rust"] as const) {
    if (part.slowest[side].ms > into.slowest[side].ms) into.slowest[side] = part.slowest[side];
  }
}

/** Bytes as text a terminal can show: printable ASCII as is, everything else \xNN. */
function printable(bytes: Uint8Array, limit = 280): string {
  let out = "";
  for (const b of bytes.subarray(0, limit)) {
    out += b >= 0x20 && b < 0x7f && b !== 0x5c ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`;
  }
  return bytes.length > limit ? `${out}… (${bytes.length} bytes)` : out;
}

const namesOf = (c: Case): string => c.applied.map((a) => a.name).join("+") || "none";

/* ---------------- one worker: judge a stripe of seeds ---------------- */

type Judge = (bytes: Uint8Array) => { ts: Outcome; rust: Outcome; kinds: string[] };

function makeJudge(impl: TsImpl, bin: string, scratch: string): Judge {
  return (bytes) => {
    const ts = tsOutcome(impl, bytes);
    const rust = rustOutcome(bin, scratch, bytes);
    return { ts, rust, kinds: findingsOf(ts, rust) };
  };
}

/** Which of a diverging case's mutations are responsible: drop them one at a time
 *  and keep each drop that leaves the same primary finding standing. */
function culpritOf(c: Case, kinds: string[], only: string[] | undefined, judge: Judge, beat: () => void): string {
  let keep = c.applied.map((a) => a.slot);
  for (const slot of [...keep]) {
    const without = keep.filter((s) => s !== slot);
    const smaller = buildCase(c.seed, { only, keep: new Set(without) });
    beat();
    if (judge(smaller.bytes).kinds.includes(kinds[0]!)) keep = without;
  }
  return c.applied.filter((a) => keep.includes(a.slot)).map((a) => a.name).join("+") || "none";
}

/** What a worker last said it was doing — all the parent has if it stops answering. */
type Heartbeat = { seed: number; names: string; label: string; tick: number };

function runSeeds(args: Args, impl: TsImpl): Result {
  const result = emptyResult();
  const scratch = join(tmpdir(), `sje-diff-${process.pid}.bin`);
  const judge = makeJudge(impl, args.bin, scratch);
  const step = args.stripe?.of ?? 1;
  const skip = new Set(args.skip);
  let tick = 0;
  const beat = (seed: number, names: string, label: string) => {
    const now: Heartbeat = { seed, names, label, tick: tick++ };
    if (args.heartbeat) writeFileSync(args.heartbeat, JSON.stringify(now));
  };
  if (args.save) mkdirSync(args.save, { recursive: true });
  try {
    for (let seed = args.start + (args.stripe?.index ?? 0); seed < args.start + args.seeds; seed += step) {
      if (skip.has(seed)) continue;
      beat(seed, "", "");
      const c = buildCase(seed, { only: args.only });
      beat(seed, namesOf(c), c.label);
      const judged = judge(c.bytes);
      const { ts, rust } = judged;
      // An unmutated document is a valid traveler by construction. If both sides refuse
      // one, the generator is wrong — and every mutated case built on such a document is
      // refused whatever its mutation did, so it tests nothing. That is a finding too.
      const kinds =
        !c.applied.length && !judged.kinds.length && !ts.verdict.accept
          ? ["unmutated refused"]
          : judged.kinds;

      result.checked++;
      if (!c.applied.length) result.unmutated++;
      if (c.applied.length === 1) result.single++;
      for (const a of c.applied) {
        const t = tallyOf(result, a.name);
        t.cases++;
        if (c.applied.length === 1) t.alone++;
      }
      if (ts.ms > result.slowest.ts.ms) result.slowest.ts = { ms: ts.ms, seed, label: c.label };
      if (rust.ms > result.slowest.rust.ms) result.slowest.rust = { ms: rust.ms, seed, label: c.label };

      if (!kinds.length) {
        if (ts.verdict.accept) result.bothAccept++;
        else result.bothRefuse++;
        continue;
      }
      const culprit = culpritOf(c, kinds, args.only, judge, () => beat(seed, namesOf(c), c.label));
      for (const name of culprit.split("+")) if (name !== "none") tallyOf(result, name).findings++;
      const finding: Finding = {
        seed,
        label: c.label,
        culprit,
        kinds,
        diffs: diffVerdicts(ts.verdict, rust.verdict),
        ts,
        rust,
        bytes: c.bytes.length,
        head: printable(c.bytes),
      };
      result.findings.push(finding);
      if (args.save) {
        writeFileSync(join(args.save, `${seed}.bin`), c.bytes);
        writeFileSync(join(args.save, `${seed}.verdicts.json`), `${JSON.stringify({ ...finding, head: undefined }, null, 2)}\n`);
      }
    }
  } finally {
    rmSync(scratch, { force: true });
  }
  return result;
}

/* ---------------- the parent: workers, and a watchdog on each ---------------- */

const SCRIPT = fileURLToPath(import.meta.url);
const running = new Set<ChildProcess>();

/** Run one worker to completion — or until it has reported nothing for HANG_MS, in
 *  which case it is killed and its last heartbeat returned instead of a result. */
function runWorker(index: number, jobs: number, dir: string, skip: number[]): Promise<Result | Heartbeat> {
  const out = join(dir, `${index}.json`);
  const heartbeat = join(dir, `${index}.beat`);
  rmSync(heartbeat, { force: true });
  const argv = [...process.execArgv, SCRIPT, ...process.argv.slice(2), "--stripe", `${index}/${jobs}`, "--result", out, "--heartbeat", heartbeat];
  if (skip.length) argv.push("--skip", skip.join(","));
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, argv, { stdio: ["ignore", "inherit", "inherit"] });
    running.add(child);
    let last = "";
    let since = Date.now();
    const watchdog = setInterval(() => {
      let now = "";
      try {
        now = readFileSync(heartbeat, "utf8");
      } catch {
        // the worker has not written one yet
      }
      if (now !== last) {
        last = now;
        since = Date.now();
      } else if (Date.now() - since >= HANG_MS) {
        settle();
        child.kill("SIGKILL");
        if (last) done(JSON.parse(last) as Heartbeat);
        else fail(new Error(`differential worker ${index} did not start within ${HANG_MS / 1000} s`));
      }
    }, 1000);
    const settle = () => {
      clearInterval(watchdog);
      running.delete(child);
      child.removeAllListeners();
    };
    child.on("error", (e) => {
      settle();
      fail(e);
    });
    child.on("exit", (code) => {
      settle();
      if (code !== 0) fail(new Error(`differential worker ${index} exited ${code}`));
      else done(JSON.parse(readFileSync(out, "utf8")) as Result);
    });
  });
}

/** One stripe of seeds, to the end: a worker that hangs is replaced by one that
 *  skips the seed it hung on, and the hang becomes a finding. */
async function runStripe(args: Args, index: number, jobs: number, dir: string): Promise<Result> {
  const hung: Finding[] = [];
  for (;;) {
    const outcome = await runWorker(index, jobs, dir, hung.map((f) => f.seed));
    if ("checked" in outcome) {
      outcome.checked += hung.length;
      outcome.findings.push(...hung);
      for (const f of hung) for (const name of f.culprit.split("+")) if (name !== "none") tallyOf(outcome, name).findings++;
      return outcome;
    }
    if (hung.length >= MAX_HANGS_PER_WORKER) throw new Error(`differential worker ${index} hung ${hung.length + 1} times — giving up`);
    // Stuck after the case was built: rebuild it here for the report (building is the
    // harness's own code and already ran once; it is the judging that never returned).
    const built = outcome.names ? buildCase(outcome.seed, { only: args.only }) : undefined;
    if (built && args.save) {
      mkdirSync(args.save, { recursive: true });
      writeFileSync(join(args.save, `${outcome.seed}.bin`), built.bytes);
    }
    hung.push({
      seed: outcome.seed,
      label: outcome.label || "(stuck while building the case — a bug in the harness, not in an implementation)",
      culprit: outcome.names || "none",
      kinds: ["ts hung"],
      diffs: [],
      ts: { verdict: REJECT, ms: HANG_MS, crash: `no answer after ${HANG_MS / 1000} s; the worker was killed` },
      rust: { verdict: REJECT, ms: 0, crash: "not reached" },
      bytes: built?.bytes.length ?? 0,
      head: built ? printable(built.bytes) : "",
    });
  }
}

/** Split the seed range across worker processes — one Rust process is spawned per
 *  case, so the work is embarrassingly parallel — and merge what they report. */
async function runWorkers(args: Args): Promise<Result> {
  const dir = join(tmpdir(), `sje-diff-${process.pid}`);
  mkdirSync(dir, { recursive: true });
  const jobs = Math.max(1, Math.min(args.jobs, args.seeds));
  try {
    const parts = await Promise.all(Array.from({ length: jobs }, (_, index) => runStripe(args, index, jobs, dir)));
    const total = emptyResult();
    for (const part of parts) merge(total, part);
    total.findings.sort((a, b) => a.seed - b.seed);
    return total;
  } finally {
    for (const child of running) child.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
}

/* ---------------- reporting ---------------- */

function report(result: Result, args: Args, impl: TsImpl): void {
  const { checked, unmutated, single, bothAccept, bothRefuse, findings, slowest } = result;
  const slow = (s: Slowest) => `${s.ms.toFixed(1)} ms (seed ${s.seed}: ${s.label.slice(0, 80)})`;
  console.log(`\ndifferential: ${checked} cases, seeds ${args.start}..${args.start + args.seeds - 1}${args.only ? ` (only ${args.only.join(",")})` : ""}`);
  console.log(`  ts   = ${impl.label}`);
  console.log(`  rust = ${args.bin}`);
  console.log(`  ${unmutated} unmutated, ${single} with one mutation, ${checked - unmutated - single} stacked; ${Object.keys(result.mutations).length} of ${CATALOG.length} mutations exercised`);
  console.log(`  both accept ${bothAccept} · both refuse ${bothRefuse} · findings ${findings.length}`);
  console.log(`  slowest: ts ${slow(slowest.ts)} · rust ${slow(slowest.rust)}`);
  if (!findings.length) {
    console.log("no findings — the implementations agree on every case, and neither crashed, hung or stalled.");
    return;
  }

  // Group by the responsible mutation(s), then by what went wrong.
  const groups = new Map<string, Map<string, number[]>>();
  for (const f of findings) {
    const byKind = groups.get(f.culprit) ?? new Map<string, number[]>();
    groups.set(f.culprit, byKind);
    for (const kind of f.kinds) byKind.set(kind, [...(byKind.get(kind) ?? []), f.seed]);
  }
  const count = (...prefixes: string[]) => findings.filter((f) => f.kinds.some((k) => prefixes.some((p) => k.startsWith(p)))).length;
  console.log(
    `\nFINDINGS: ${findings.length} cases — ${count("ts accepts", "ts refuses")} accept/refuse splits, ` +
      `${count("hash", "level", "bound")} hash/level/bound splits, ${count("ts crashed")} ts crashes, ` +
      `${count("rust crashed")} rust crashes, ${count("ts hung")} hangs, ${count("ts slow", "rust slow")} slow, ` +
      `${count("unmutated refused")} unmutated documents refused`,
  );
  console.log("by responsible mutation (the smallest subset of a case's mutations that still reproduces):");
  for (const [culprit, byKind] of [...groups].sort((a, b) => a[0].localeCompare(b[0]))) {
    for (const [kind, seeds] of byKind) {
      console.log(`  ${culprit.padEnd(34)} ${String(seeds.length).padStart(5)} × ${kind.padEnd(26)} seeds ${seeds.slice(0, 6).join(", ")}${seeds.length > 6 ? ", …" : ""}`);
    }
  }
  if (args.quiet) return;
  console.log("\nexamples (first of each group; reproduce one with --start <seed> --seeds 1):");
  const shown = new Set<string>();
  for (const f of findings) {
    const key = `${f.culprit}|${f.kinds[0]}`;
    if (shown.has(key) || shown.size >= 20) continue;
    shown.add(key);
    console.log(`\n  seed ${f.seed}  ${f.label}`);
    console.log(`    ${f.kinds.join(" | ")}${f.diffs.length ? `   (${f.diffs.join(" | ").slice(0, 300)})` : ""}`);
    if (f.ts.crash) console.log(`    ts:   ${f.ts.crash}`);
    if (f.rust.crash && !f.kinds.includes("ts hung")) console.log(`    rust: ${f.rust.crash}`);
    console.log(`    ${f.head}`);
  }
}

/* ---------------- replaying saved bytes ---------------- */

function replay(args: Args, impl: TsImpl): number {
  const target = args.replay!;
  // In a directory: every file except notes (*.md) and --save's verdict sidecars.
  const files = statSync(target).isDirectory()
    ? readdirSync(target)
        .filter((f) => !f.endsWith(".md") && !f.endsWith(".verdicts.json"))
        .sort()
        .map((f) => join(target, f))
    : [target];
  const scratch = join(tmpdir(), `sje-replay-${process.pid}.bin`);
  const judge = makeJudge(impl, args.bin, scratch);
  let found = 0;
  try {
    for (const file of files) {
      const bytes = readFileSync(file);
      const { ts, rust, kinds } = judge(bytes);
      if (kinds.length) found++;
      console.log(`${file} (${bytes.length} bytes): ${kinds.length ? kinds.join(" | ") : "no finding"}`);
      console.log(`  ts   ${ts.crash ?? JSON.stringify(ts.verdict)}  [${ts.ms.toFixed(1)} ms]`);
      console.log(`  rust ${rust.crash ?? JSON.stringify(rust.verdict)}  [${rust.ms.toFixed(1)} ms]`);
    }
  } finally {
    rmSync(scratch, { force: true });
  }
  console.log(`\nreplay: ${files.length} files, ${found} with a finding`);
  return found;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const impl = await loadTsImpl(args.tsRoot);
  if (args.replay) process.exit(replay(args, impl) ? 1 : 0);
  if (args.stripe) {
    // A worker: do the stripe, hand the result to the parent.
    writeFileSync(args.result!, JSON.stringify(runSeeds(args, impl)));
    return;
  }
  const result = await runWorkers(args);
  report(result, args, impl);
  if (args.report) writeFileSync(args.report, `${JSON.stringify({ args, ts: impl.label, ...result }, null, 2)}\n`);
  process.exit(result.findings.length ? 1 : 0);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(2);
});
