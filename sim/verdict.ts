/** The cross-implementation "verdict" — the four decisions both implementations
 *  must agree on for any document: does it parse, what does it hash to, what
 *  level is it, and which quotes bind. The differential harness compares the
 *  TypeScript verdict (computed in-process) against the Rust verdict (the
 *  `envelope check` CLI) for the same bytes; any field that differs is a break.
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { parseTraveler, levelOf, boundQuotes } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";

export type Verdict = {
  accept: boolean;
  hash: string | null;
  level: string | null;
  bound: string[] | null;
};

export const REJECT: Verdict = { accept: false, hash: null, level: null, bound: null };

/** The TypeScript reference verdict. Mirrors exactly what `envelope check` does
 *  in Rust: parse; if it parses, hash (null if unhashable), level, sorted bound
 *  quote ids. Every step is guarded so the harness never crashes on hostile input
 *  — a thrown verifier is itself a finding, surfaced as accept:false rather than
 *  an uncaught exception. */
export function tsVerdict(doc: unknown): Verdict {
  let traveler;
  try {
    traveler = parseTraveler(doc);
  } catch {
    return REJECT;
  }
  let hash: string | null = null;
  try {
    hash = travelerHash(traveler);
  } catch {
    hash = null;
  }
  let level: string | null = null;
  try {
    level = levelOf(traveler).code;
  } catch {
    level = null;
  }
  let bound: string[] = [];
  try {
    bound = boundQuotes(traveler)
      .map((q) => q.quote_id)
      .sort();
  } catch {
    bound = [];
  }
  return { accept: true, hash, level, bound };
}

/** The Rust verdict, via the release CLI. `bin` is the compiled `envelope`
 *  binary; `scratch` is a path the harness may write the document to (the CLI
 *  reads a file). */
export function rustVerdict(bin: string, scratch: string, json: string): Verdict {
  writeFileSync(scratch, json);
  const out = execFileSync(bin, ["check", scratch], { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  return JSON.parse(out) as Verdict;
}

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
