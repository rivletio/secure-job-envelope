/** The cross-implementation "verdict" — the four decisions both implementations
 *  must agree on for any document: does it parse, what does it hash to, what
 *  level is it, and which quotes bind.
 *
 *  Both sides are asked about the same BYTES. The Rust side reads them from a file
 *  (`envelope check`); the TypeScript side is handed them through its strict text
 *  entry point, `parseTravelerJson(bytes)`. Nothing here ever gives TypeScript a
 *  value some other code parsed first: a duplicate member name, a byte-order mark, an
 *  escaped name or a byte that is not UTF-8 exists only in the bytes, and the old
 *  harness — which compared `parseTraveler(JSON.parse(text))` — was blind to all four.
 *
 *  Besides its verdict each side reports how long it took and whether it failed to
 *  answer at all (a crash is a finding in its own right, not a refusal).
 */
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { boundQuotes, levelOf, parseTravelerJson } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";

export type Verdict = {
  accept: boolean;
  hash: string | null;
  level: string | null;
  bound: string[] | null;
};

export const REJECT: Verdict = { accept: false, hash: null, level: null, bound: null };

/** One implementation's answer for one document. `crash` is set when it gave no
 *  answer: an exception that is not a refusal, a panic, a non-zero exit, a timeout. */
export type Outcome = { verdict: Verdict; ms: number; crash?: string };

/** Either side taking longer than this on one document (at most 512 KiB of it is
 *  ever read) is a finding: a hostile document must be cheap to refuse. */
export const SLOW_MS = 2000;
/** How long the Rust CLI may run before the harness gives up on it. */
const RUST_TIMEOUT_MS = 10_000;

/* ---------------- TypeScript ---------------- */

/** The four functions the verdict needs, from one checkout's TypeScript reference. */
export type TsImpl = {
  /** For reports: which code answered. */
  label: string;
  /** Wire bytes -> traveler, or throw. */
  parse: (bytes: Uint8Array) => unknown;
  travelerHash: (traveler: any) => string;
  levelOf: (traveler: any) => { code: string };
  boundQuotes: (traveler: any) => { quote_id: string }[];
};

const HEAD: TsImpl = { label: "this checkout (parseTravelerJson)", parse: parseTravelerJson, travelerHash, levelOf, boundQuotes };

/** The TypeScript reference of this checkout, or — given `root` — of another one
 *  (`--ts-root`), loaded from its own `src/lib/traveler` with its own dependencies.
 *  That is how the fuzzer is tested against the commits whose bugs it must be able to
 *  find: point it at a checkout that still has them. */
export async function loadTsImpl(root?: string): Promise<TsImpl> {
  if (!root) return HEAD;
  const load = (file: string) => import(pathToFileURL(resolve(root, "src/lib/traveler", file)).href);
  const conformance = await load("conformance.ts");
  const hash = await load("hash.ts");
  const fns = { travelerHash: hash.travelerHash, levelOf: conformance.levelOf, boundQuotes: conformance.boundQuotes };
  if (typeof conformance.parseTravelerJson === "function") {
    return { label: `${root} (parseTravelerJson)`, parse: conformance.parseTravelerJson, ...fns };
  }
  // A checkout from before the strict text boundary has no parseTravelerJson. What
  // its callers did with wire bytes was decode them with the platform defaults and
  // JSON.parse the text — the desk's file open, the archive reader and the MCP string
  // argument all came down to `parseTraveler(JSON.parse(text))`. So that, and not
  // some stricter stand-in, is the faithful emulation of the old tree: TextDecoder's
  // defaults strip a byte-order mark and turn invalid UTF-8 into U+FFFD, and
  // JSON.parse keeps the last of a repeated member — exactly the habits under test.
  const legacy = (bytes: Uint8Array): unknown => {
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      throw new Error("not JSON");
    }
    return conformance.parseTraveler(value);
  };
  return { label: `${root} (legacy: parseTraveler(JSON.parse(decode(bytes))))`, parse: legacy, ...fns };
}

/** A refusal is a plain `Error` — what the reference throws on purpose. Anything
 *  else (a RangeError from a blown stack, a TypeError from a shape nobody expected)
 *  is the implementation failing to decide, and is reported as a crash. */
const isRefusal = (e: unknown): boolean => e instanceof Error && e.name === "Error";

function decide(impl: TsImpl, bytes: Uint8Array): Verdict {
  let traveler: unknown;
  try {
    traveler = impl.parse(bytes);
  } catch (e) {
    if (isRefusal(e)) return REJECT;
    throw e;
  }
  // Mirrors `check_verdict` in the Rust core: hash (null if unhashable), level,
  // sorted bound quote ids.
  const attempt = <T>(fn: () => T, otherwise: T): T => {
    try {
      return fn();
    } catch (e) {
      if (isRefusal(e)) return otherwise;
      throw e;
    }
  };
  const hash = attempt<string | null>(() => impl.travelerHash(traveler), null);
  const level = attempt<string | null>(() => impl.levelOf(traveler).code, null);
  const bound = attempt(() => impl.boundQuotes(traveler).map((q) => q.quote_id).sort(), [] as string[]);
  return { accept: true, hash, level, bound };
}

/** The TypeScript verdict for these bytes. Never throws. */
export function tsOutcome(impl: TsImpl, bytes: Uint8Array): Outcome {
  const started = performance.now();
  try {
    const verdict = decide(impl, bytes);
    return { verdict, ms: performance.now() - started };
  } catch (e) {
    const what = e instanceof Error ? `${e.name}: ${e.message}` : `threw ${typeof e}`;
    return { verdict: REJECT, ms: performance.now() - started, crash: what.slice(0, 200) };
  }
}

/* ---------------- Rust ---------------- */

const isVerdict = (v: unknown): v is Verdict =>
  !!v && typeof v === "object" && typeof (v as Verdict).accept === "boolean" && "hash" in v && "level" in v && "bound" in v;

/** The Rust verdict for these bytes, via the release CLI: the bytes are written to
 *  `scratch` and `<bin> check <scratch>` is run. `check` prints a verdict and exits 0
 *  for every input, so anything else — a panic, a non-zero exit, no parseable verdict,
 *  no answer in time — is reported as a crash. Throws only if the CLI cannot be run. */
export function rustOutcome(bin: string, scratch: string, bytes: Uint8Array): Outcome {
  writeFileSync(scratch, bytes);
  const started = performance.now();
  const run = spawnSync(bin, ["check", scratch], {
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    timeout: RUST_TIMEOUT_MS,
  });
  const ms = performance.now() - started;
  const crashed = (crash: string): Outcome => ({ verdict: REJECT, ms, crash: crash.slice(0, 200) });
  if (run.error) {
    const code = (run.error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "EACCES") {
      throw new Error(
        `cannot run the Rust CLI at ${bin} — build it first: cargo build --release --manifest-path crates/secure-job-envelope/Cargo.toml`,
      );
    }
    return crashed(code === "ETIMEDOUT" ? `no verdict after ${RUST_TIMEOUT_MS} ms` : run.error.message);
  }
  if (run.status !== 0) {
    const firstLine = (run.stderr ?? "").split("\n")[0] ?? "";
    return crashed(`exit ${run.status ?? run.signal} without a verdict: ${firstLine}`);
  }
  try {
    const verdict: unknown = JSON.parse(run.stdout);
    if (isVerdict(verdict)) return { verdict, ms };
  } catch {
    // fall through
  }
  return crashed(`exit 0 but no verdict on stdout: ${run.stdout.slice(0, 80)}`);
}

/* ---------------- comparison ---------------- */

/** Compare two verdicts; returns a list of human-readable field mismatches
 *  (empty when they agree). Order-independent for `bound` (both sides sort). */
export function diffVerdicts(ts: Verdict, rs: Verdict): string[] {
  const out: string[] = [];
  if (ts.accept !== rs.accept) out.push(`accept: ts=${ts.accept} rs=${rs.accept}`);
  // Only compare the downstream fields when both accepted; a reject on one side is
  // already reported above and its null fields would just add noise.
  if (ts.accept && rs.accept) {
    if (ts.hash !== rs.hash) out.push(`hash: ts=${ts.hash} rs=${rs.hash}`);
    if (ts.level !== rs.level) out.push(`level: ts=${ts.level} rs=${rs.level}`);
    const a = JSON.stringify(ts.bound);
    const b = JSON.stringify(rs.bound);
    if (a !== b) out.push(`bound: ts=${a} rs=${b}`);
  }
  return out;
}

/** Everything wrong with one case, as short stable strings a report can group by:
 *  a field the two verdicts differ on (with its direction, never its values), a
 *  crash, or a side that was too slow. Empty when the case is clean. */
export function findingsOf(ts: Outcome, rs: Outcome): string[] {
  const out: string[] = [];
  if (ts.crash) out.push("ts crashed");
  if (rs.crash) out.push("rust crashed");
  if (ts.ms > SLOW_MS) out.push("ts slow");
  if (rs.ms > SLOW_MS) out.push("rust slow");
  if (ts.crash || rs.crash) return out;
  const a = ts.verdict;
  const b = rs.verdict;
  if (a.accept !== b.accept) out.push(a.accept ? "ts accepts, rust refuses" : "ts refuses, rust accepts");
  if (a.accept && b.accept) {
    if (a.hash !== b.hash) out.push("hash differs");
    if (a.level !== b.level) out.push(`level ts=${a.level} rust=${b.level}`);
    if (JSON.stringify(a.bound) !== JSON.stringify(b.bound)) out.push("bound differs");
  }
  return out;
}
