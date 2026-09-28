/** Cross-implementation differential fuzzer.
 *
 *  For each seed it builds a valid traveler, optionally applies one adversarial
 *  mutation that pushes a field to or past a boundary, then asks BOTH
 *  implementations for their verdict (parse / hash / level / bound) on the exact
 *  same bytes. Any disagreement is a break: the two codebases are supposed to be
 *  interchangeable, so a document that one accepts and the other rejects — or that
 *  they hash differently — undermines the whole content-addressing premise.
 *
 *  Deterministic in the seed range, so every failure reproduces exactly. Exits
 *  non-zero if any divergence is found, so CI fails loudly.
 *
 *  Run: node --experimental-strip-types sim/differential.ts [--seeds N] [--start S]
 *       [--bin <path>] [--corpus <dir>] [--quiet]
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { Rng } from "./rng.ts";
import { genPlan, genTraveler } from "./generate.ts";
import { MUTATIONS, type Doc } from "./mutations.ts";
import { diffVerdicts, rustVerdict, tsVerdict, type Verdict } from "./verdict.ts";

type Args = { seeds: number; start: number; bin: string; corpus?: string; quiet: boolean };

function parseArgs(argv: string[]): Args {
  const a: Args = {
    seeds: 2000,
    start: 1,
    bin: "crates/secure-job-envelope/target/release/envelope",
    quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === "--seeds") a.seeds = Number(argv[++i]);
    else if (v === "--start") a.start = Number(argv[++i]);
    else if (v === "--bin") a.bin = argv[++i]!;
    else if (v === "--corpus") a.corpus = argv[++i];
    else if (v === "--quiet") a.quiet = true;
  }
  return a;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const scratch = `${process.env.TMPDIR ?? "/tmp"}/sje-diff-${process.pid}.json`;
  if (args.corpus) mkdirSync(args.corpus, { recursive: true });

  let checked = 0;
  const byField: Record<string, number> = {};
  const byMutation: Record<string, number> = {};
  const examples: Array<{ seed: number; mutation: string; json: string; ts: Verdict; rs: Verdict; diffs: string[] }> = [];

  for (let seed = args.start; seed < args.start + args.seeds; seed++) {
    const rng = new Rng(seed);
    const traveler = genTraveler(rng, genPlan(rng));
    const doc = structuredClone(traveler) as Doc;

    // ~55% of docs get exactly one mutation; the rest stay valid (they still
    // exercise hash/level/bound parity on well-formed input, where D1/D4/D5 lived).
    let mutation = "none";
    if (rng.bool(0.55)) {
      const m = rng.pick(MUTATIONS);
      mutation = m.name;
      m.apply(doc);
    }

    const json = JSON.stringify(doc);
    let ts: Verdict;
    try {
      ts = tsVerdict(JSON.parse(json));
    } catch (e) {
      ts = { accept: false, hash: null, level: null, bound: null };
      if (!args.quiet) console.error(`ts threw on seed ${seed} (${mutation}): ${String(e)}`);
    }
    const rs = rustVerdict(args.bin, scratch, json);

    checked++;
    const diffs = diffVerdicts(ts, rs);
    if (diffs.length) {
      for (const d of diffs) byField[d.split(":")[0]!] = (byField[d.split(":")[0]!] ?? 0) + 1;
      byMutation[mutation] = (byMutation[mutation] ?? 0) + 1;
      if (examples.length < 25) examples.push({ seed, mutation, json, ts, rs, diffs });
      if (args.corpus) writeFileSync(`${args.corpus}/div-${seed}-${mutation}.json`, json);
    }
  }

  const mismatches = Object.values(byMutation).reduce((a, b) => a + b, 0);
  console.log(`\ndifferential: checked ${checked} docs, ${mismatches} divergent`);
  if (mismatches) {
    console.log("by field:", byField);
    console.log("by mutation:", byMutation);
    console.log("\nfirst examples:");
    for (const e of examples.slice(0, 15)) {
      console.log(`\n  seed=${e.seed} mutation=${e.mutation}`);
      console.log(`  diffs: ${e.diffs.join(" | ")}`);
      console.log(`  doc: ${e.json.slice(0, 400)}`);
    }
    process.exit(1);
  }
  console.log("no divergences — implementations agree on every document.");
}

main();
