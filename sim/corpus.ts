/** Generates the committed cross-implementation fuzz corpus.
 *
 *  A deterministic slice of the differential, frozen to disk so the Rust core can
 *  replay it in `cargo test` (tests/fuzz_corpus.rs) with no Node in the loop: each
 *  document's exact bytes plus the TypeScript reference verdict (parse / hash /
 *  level / bound). Rust recomputes the verdict for the same bytes and must match.
 *
 *  Documents that cannot round-trip through a file serde can read (lone surrogates)
 *  are excluded — the harness exercises those in-process, and a reject vector pins
 *  them separately.
 *
 *  Run: node --experimental-strip-types sim/corpus.ts [count]
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { Rng } from "./rng.ts";
import { genPlan, genTraveler } from "./generate.ts";
import { MUTATIONS } from "./mutations.ts";
import { tsVerdict } from "./verdict.ts";

const count = Number(process.argv[2] ?? 400);
const jsonSafe = MUTATIONS.filter((m) => m.jsonSafe !== false);

const travelers: string[] = [];
const expected: string[] = [];

for (let i = 1; i <= count; i++) {
  // Sample a different seed region than the live differential for extra coverage.
  const rng = new Rng(1_000_000 + i);
  const doc = structuredClone(genTraveler(rng, genPlan(rng))) as Record<string, any>;
  if (rng.bool(0.5)) rng.pick(jsonSafe).apply(doc);
  const json = JSON.stringify(doc);
  travelers.push(json);
  expected.push(JSON.stringify(tsVerdict(JSON.parse(json))));
}

const dir = new URL("../conformance/fuzz/", import.meta.url).pathname;
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}travelers.jsonl`, travelers.join("\n") + "\n");
writeFileSync(`${dir}expected.jsonl`, expected.join("\n") + "\n");

const accepted = expected.filter((e) => (JSON.parse(e) as { accept: boolean }).accept).length;
console.log(
  `wrote ${count} corpus documents to conformance/fuzz/ (${accepted} accepted, ${count - accepted} rejected)`,
);
