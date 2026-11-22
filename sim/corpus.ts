/** Generates the committed cross-implementation fuzz corpus (conformance/fuzz).
 *
 *  A deterministic selection of fuzz cases, frozen to disk so each implementation
 *  can replay it in its own test run with nothing else in the loop: the Rust core in
 *  `cargo test` (crates/…/tests/fuzz_corpus.rs), the TypeScript reference in
 *  `npm test` (sim/corpus.test.ts). A case is its exact wire BYTES — one file per
 *  case, because some are not UTF-8, start with a byte-order mark or end in a NUL,
 *  and no line-oriented text format survives that — plus one manifest line with the
 *  TypeScript reference verdict (parse / hash / level / bound).
 *
 *  Selection is coverage-driven, not "the first N seeds": scanning seeds upward from
 *  1,000,001 it takes
 *    - the first cases in which each mutation is the ONLY one applied (one for a
 *      fixed field mutation, three — each a different variant — for a family),
 *    - some unmutated travelers and some stacked cases,
 *  skipping any case too large to commit (the half-megabyte size-cap cases stay in
 *  the live fuzzer; the mutations marked `liveOnly` produce nothing else).
 *
 *  Only AGREED verdicts are frozen. Each candidate is also put to the Rust CLI; one
 *  the two implementations judge differently is an open finding (sim/findings), not a
 *  regression vector — it is reported and left out. Every case here is `buildCase` of
 *  its seed, so `npm run differential -- --start <seed> --seeds 1` reproduces it.
 *
 *  Run: node --experimental-strip-types sim/corpus.ts [--bin <path to envelope>]
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha384Hex } from "../src/lib/traveler/hash.ts";
import { buildCase, CATALOG, drawnNames, mutationNamed, showApplied } from "./case.ts";
import { FIELD_MUTATIONS } from "./mutations.ts";
import { diffVerdicts, loadTsImpl, rustOutcome, tsOutcome, type Verdict } from "./verdict.ts";

const FIRST_SEED = 1_000_001; // a different region than the live differential's
const SCAN_LIMIT = 60_000;
const MAX_CASE_BYTES = 12 * 1024;
const UNMUTATED = 24;
const STACKED = 48;
/** A field mutation is one fixed edit; a family picks among variants. */
const FIXED = new Set(FIELD_MUTATIONS.map((m) => m.name));
const quota = (name: string): number => (mutationNamed(name).liveOnly ? 0 : FIXED.has(name) ? 1 : 3);

export type ManifestEntry = {
  file: string;
  seed: number;
  /** Each applied mutation as `name[variant]`; empty for an unmutated traveler. */
  mutations: string[];
  bytes: number;
  sha384: string;
  expected: Verdict;
};

const binFlag = process.argv.indexOf("--bin");
const bin = binFlag >= 0 ? process.argv[binFlag + 1]! : "crates/secure-job-envelope/target/release/envelope";
const impl = await loadTsImpl();
const scratch = join(tmpdir(), `sje-corpus-${process.pid}.bin`);

const taken = new Map<string, Set<string>>(CATALOG.map((m) => [m.name, new Set<string>()]));
const wanted = () => CATALOG.filter((m) => taken.get(m.name)!.size < quota(m.name));
let unmutated = 0;
let stacked = 0;
const entries: ManifestEntry[] = [];
const files = new Map<string, Uint8Array>();
const open: number[] = [];

let seed = FIRST_SEED;
for (; seed < FIRST_SEED + SCAN_LIMIT; seed++) {
  if (unmutated >= UNMUTATED && stacked >= STACKED && !wanted().length) break;
  // Decide from the draw alone whether this seed could be useful, before building it.
  const drawn = drawnNames(seed);
  if (drawn.some((n) => mutationNamed(n).liveOnly)) continue;
  if (drawn.length === 0 && unmutated >= UNMUTATED) continue;
  if (drawn.length === 1 && taken.get(drawn[0]!)!.size >= quota(drawn[0]!)) continue;
  if (drawn.length > 1 && stacked >= STACKED) continue;

  const c = buildCase(seed);
  if (c.bytes.length > MAX_CASE_BYTES || c.applied.length !== drawn.length) continue; // too big, or one did not bite
  const variant = c.applied[0]?.detail ?? "";
  if (drawn.length === 1 && taken.get(drawn[0]!)!.has(variant)) continue; // that variant is already in

  // Agreement is about the verdict (and neither side crashing) — not about how long
  // this machine took, which must never decide what is in a committed file.
  const ts = tsOutcome(impl, c.bytes);
  const rust = rustOutcome(bin, scratch, c.bytes);
  if (ts.crash || rust.crash || diffVerdicts(ts.verdict, rust.verdict).length) {
    open.push(seed);
    continue;
  }

  if (drawn.length === 0) unmutated++;
  else if (drawn.length === 1) taken.get(drawn[0]!)!.add(variant);
  else stacked++;
  const file = `cases/${seed}.bin`;
  files.set(file, c.bytes);
  entries.push({ file, seed, mutations: c.applied.map(showApplied), bytes: c.bytes.length, sha384: sha384Hex(c.bytes), expected: ts.verdict });
}
rmSync(scratch, { force: true });

const missing = CATALOG.filter((m) => quota(m.name) > 0 && taken.get(m.name)!.size === 0).map((m) => m.name);
if (missing.length) {
  console.error(
    `no committable case found for: ${missing.join(", ")}\n` +
      `(scanned ${SCAN_LIMIT} seeds; a mutation whose cases are all over ${MAX_CASE_BYTES} bytes must be marked liveOnly)`,
  );
  process.exit(1);
}

const dir = new URL("../conformance/fuzz/", import.meta.url).pathname;
rmSync(`${dir}cases`, { recursive: true, force: true });
mkdirSync(`${dir}cases`, { recursive: true });
for (const [file, bytes] of files) writeFileSync(`${dir}${file}`, bytes);
writeFileSync(`${dir}manifest.jsonl`, entries.map((e) => `${JSON.stringify(e)}\n`).join(""));

const accepted = entries.filter((e) => e.expected.accept).length;
const total = entries.reduce((n, e) => n + e.bytes, 0);
console.log(
  `wrote ${entries.length} corpus cases to conformance/fuzz/ (${accepted} accepted, ${entries.length - accepted} refused; ` +
    `${total} bytes; seeds ${FIRST_SEED}..${seed - 1} scanned)`,
);
console.log(
  `  ${CATALOG.length - CATALOG.filter((m) => m.liveOnly).length} mutations each alone, ${unmutated} unmutated, ${stacked} stacked; ` +
    `live-only (too large to commit): ${CATALOG.filter((m) => m.liveOnly).map((m) => m.name).join(", ")}`,
);
if (open.length) {
  console.log(
    `  ${open.length} candidate${open.length > 1 ? "s" : ""} NOT frozen — the implementations disagree on them (open findings, see sim/findings): ` +
      `seeds ${open.join(", ")}`,
  );
}
