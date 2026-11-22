import { travelerHash } from "./hash.ts";
import { LONE_SURROGATE } from "./canonical.ts";
import { travelerSchema, quoteSchema } from "./schema.ts";
import type { ConformanceLevel, Traveler, Quote } from "./types.ts";

/** Reject what the Rust core's serde_json refuses at parse time, so the two
 *  implementations accept and reject the same documents. Three parse-time
 *  divergences are closed here, before the zod schema runs:
 *   - a lone surrogate in ANY string key or value: it has no UTF-8 encoding, so
 *     serde_json cannot parse the document (and the string would be unhashable);
 *   - a non-finite number: `JSON.parse("1e309")` yields `Infinity`, which a blob's
 *     `z.unknown()` would accept, but serde_json errors on an out-of-range float —
 *     so without this TypeScript would accept a document Rust rejects;
 *   - nesting past serde_json's 128-container recursion limit.
 *  `depth` counts the containers enclosing `v` (the root value is enclosed by 0);
 *  a container that is the 128th or deeper is the one serde_json refuses.
 *
 *  It also refuses a member named `__proto__` anywhere. This one is the reverse case —
 *  a divergence that originates on THIS side: zod's `z.record` (the free-form blobs)
 *  silently drops an own `__proto__` key, so TypeScript would canonicalize, sign and
 *  verify bytes that omit wire content the Rust core keeps. One document, two signature
 *  verdicts — the signer could choose which implementation accepts it. The Rust
 *  validator refuses the same name, so both sides agree by refusing. */
// serde_json's RECURSION_LIMIT. Matched exactly (verified against the Rust parser at
// the 127/128 boundary) so a deeply-nested blob is refused on the same side as Rust,
// not accepted here and rejected there — and so a deep document is refused cleanly
// rather than blowing the stack with an uncaught RangeError.
const MAX_JSON_DEPTH = 128;

function assertUtf8Safe(v: unknown, depth = 0): void {
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new Error("string contains a lone surrogate (no UTF-8 encoding)");
    return;
  }
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number has no JSON form serde_json will parse");
    return;
  }
  if (Array.isArray(v)) {
    if (depth + 1 >= MAX_JSON_DEPTH) throw new Error("JSON nesting exceeds the maximum depth");
    for (const x of v) assertUtf8Safe(x, depth + 1);
    return;
  }
  if (v && typeof v === "object") {
    if (depth + 1 >= MAX_JSON_DEPTH) throw new Error("JSON nesting exceeds the maximum depth");
    for (const [k, val] of Object.entries(v)) {
      if (k === "__proto__") throw new Error("a member named __proto__ is not permitted");
      if (LONE_SURROGATE.test(k)) throw new Error("object key contains a lone surrogate (no UTF-8 encoding)");
      assertUtf8Safe(val, depth + 1);
    }
  }
}

export type LevelInfo = {
  level: ConformanceLevel;
  name: "Draft" | "Quoteable" | "Awardable" | "Executable" | "As-built";
  code: "D" | "L0" | "L1" | "L2" | "L3";
  missing: string[];
};

export function isQuoteable(traveler: Traveler): boolean {
  return (
    traveler.buyer.name.trim().length > 0 &&
    traveler.part.family.trim().length > 0 &&
    traveler.part.part_number.trim().length > 0 &&
    traveler.part.material.spec.trim().length > 0 &&
    traveler.part.qty.target >= 1
  );
}

export function boundQuotes(traveler: Traveler): Quote[] {
  const hash = travelerHash(traveler);
  return (traveler.quotes ?? []).filter((q) => {
    const parsed = quoteSchema.safeParse(q);
    if (!parsed.success) return false;
    if (q.traveler_hash_quoted !== hash) return false;
    if (traveler.itar && q.seller.itar !== true) return false;
    return true;
  });
}

export function staleQuotes(traveler: Traveler): Quote[] {
  const hash = travelerHash(traveler);
  return (traveler.quotes ?? []).filter((q) => q.traveler_hash_quoted !== hash);
}

export function awardedQuote(traveler: Traveler): Quote | undefined {
  if (!traveler.award) return undefined;
  return boundQuotes(traveler).find((q) => q.quote_id === traveler.award?.quote_id);
}

export function levelOf(traveler: Traveler): LevelInfo {
  const missing: string[] = [];
  if (!traveler.buyer.name.trim()) missing.push("buyer.name");
  if (!traveler.part.family.trim()) missing.push("part.family");
  if (!traveler.part.part_number.trim()) missing.push("part.part_number");
  if (!traveler.part.material.spec.trim()) missing.push("part.material.spec");
  if (!(traveler.part.qty.target >= 1)) missing.push("part.qty.target");

  if (missing.length) {
    return { level: 0, name: "Draft", code: "D", missing };
  }

  const bound = boundQuotes(traveler);
  if (bound.length === 0) {
    return {
      level: 0,
      name: "Quoteable",
      code: "L0",
      missing: ["bound quote (traveler_hash_quoted)"],
    };
  }

  const awardOk = Boolean(traveler.award && bound.some((q) => q.quote_id === traveler.award?.quote_id));
  const opsOk = (traveler.ops ?? []).length >= 1;
  const shipOk = Boolean(
    traveler.ship_to?.name && traveler.ship_to.line1 && traveler.ship_to.city && traveler.ship_to.country,
  );

  if (!awardOk || !opsOk || !shipOk) {
    const l1missing: string[] = [];
    if (!awardOk) l1missing.push("award bound to current revision");
    if (!opsOk) l1missing.push("ops[]");
    if (!shipOk) l1missing.push("ship_to");
    return { level: 1, name: "Awardable", code: "L1", missing: l1missing };
  }

  if (traveler.as_built && Object.keys(traveler.as_built).length > 0) {
    return { level: 3, name: "As-built", code: "L3", missing: [] };
  }

  return {
    level: 2,
    name: "Executable",
    code: "L2",
    missing: ["as_built (record L3 as-built data to advance)"],
  };
}

export function parseTraveler(data: unknown): Traveler {
  assertUtf8Safe(data);
  const r = travelerSchema.safeParse(data);
  if (!r.success) throw new Error(formatZod(r.error, "traveler"));
  return r.data as Traveler;
}

export function parseQuote(data: unknown): Quote {
  assertUtf8Safe(data);
  const r = quoteSchema.safeParse(data);
  if (!r.success) throw new Error(formatZod(r.error, "quote"));
  return r.data as Quote;
}

/** Apply an amend patch to a traveler and re-validate it — shared by the desk store
 *  and the MCP sje_amend handler so both bump the revision and force the SAME key set.
 *  A patch may only change the quoteable body: identity, quotes, award, ship-to, ops,
 *  and as_built are pinned so a patch can't inject lifecycle state, and the buyer
 *  signatures — necessarily invalid once the revision bump moves `traveler_hash` — are
 *  dropped rather than carried forward stale. Throws (via parseTraveler) on a malformed
 *  result. Caller is responsible for the lock check (an amend of a locked traveler). */
export function amendMerge(current: Traveler, patch: Partial<Traveler>): Traveler {
  return parseTraveler({
    ...current,
    ...patch,
    spec: current.spec,
    traveler_id: current.traveler_id,
    created_at: current.created_at,
    revision: current.revision + 1,
    quotes: current.quotes,
    award: null,
    ship_to: current.ship_to,
    ops: current.ops,
    as_built: current.as_built ?? null,
    signatures: undefined,
  });
}

function formatZod(err: { issues: { path: PropertyKey[]; message: string }[] }, kind: string): string {
  const issue = err.issues[0];
  if (!issue) return `Invalid ${kind}`;
  const path = issue.path.length ? `${issue.path.map(String).join(".")}: ` : "";
  return `Invalid ${kind}. ${path}${issue.message}`;
}
