import { travelerHash } from "./hash.ts";
import { LONE_SURROGATE } from "./canonical.ts";
import { travelerSchema, quoteSchema } from "./schema.ts";
import type { ConformanceLevel, Traveler, Quote } from "./types.ts";

/** Reject a document containing a lone surrogate in ANY string key or value.
 *  Such a string has no UTF-8 encoding, so the Rust core's serde_json refuses the
 *  whole document at parse; without this check TypeScript would accept a document
 *  Rust rejects (a cross-implementation accept/reject divergence), and the
 *  offending string would also be unhashable. Mirrors serde's parse-time refusal. */
function assertUtf8Safe(v: unknown): void {
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new Error("string contains a lone surrogate (no UTF-8 encoding)");
    return;
  }
  if (Array.isArray(v)) {
    for (const x of v) assertUtf8Safe(x);
    return;
  }
  if (v && typeof v === "object") {
    for (const [k, val] of Object.entries(v)) {
      if (LONE_SURROGATE.test(k)) throw new Error("object key contains a lone surrogate (no UTF-8 encoding)");
      assertUtf8Safe(val);
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
    missing: ["as_built (reserved in 0.0.1)"],
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

function formatZod(err: { issues: { path: PropertyKey[]; message: string }[] }, kind: string): string {
  const issue = err.issues[0];
  if (!issue) return `Invalid ${kind}`;
  const path = issue.path.length ? `${issue.path.map(String).join(".")}: ` : "";
  return `Invalid ${kind}. ${path}${issue.message}`;
}
