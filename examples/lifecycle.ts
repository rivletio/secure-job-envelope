/** Worked example: the SJE lifecycle — compose, quote, amend, re-quote, award.
 *
 *  Runs the real store state machine (src/lib/traveler/store.ts) — the same code
 *  the browser desk drives — to show the two properties that let the file stand
 *  in as a system of record on its own: a quote binds to the EXACT revision it
 *  priced (amend the spec and it goes stale), and an awarded (L2) traveler locks.
 *
 *  Run: npm run example:lifecycle
 */
import assert from "node:assert/strict";
import { useTravelerStore } from "../src/lib/traveler/store.ts";
import { boundQuotes, levelOf, staleQuotes } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";
import { locked } from "../src/lib/traveler/guards.ts";
import { isoNow, newQuoteId, newTravelerId } from "../src/lib/traveler/ids.ts";
import type { Quote, Traveler } from "../src/lib/traveler/types.ts";

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);
const short = (h: string) => `${h.slice(0, 24)}…`;
const store = useTravelerStore.getState();

console.log("=== SJE lifecycle: compose → quote → amend → re-quote → award ===");

/* 1. The buyer composes an L0 (Quoteable) traveler — material and quantity known. */
step(1, "Buyer composes an L0 (Quoteable) traveler");
const l0: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: newTravelerId(),
  revision: 1,
  created_at: isoNow(),
  buyer: { org_id: "org_northline", name: "Northline Equipment", city: "Reno", region: "NV" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6", form: "plate", thickness_mm: 6.35 },
    qty: { target: 250, breaks: [100, 250, 500] },
    processes: ["laser", "cnc-mill", "deburr"],
  },
  need_by: "2026-12-01",
  incoterms: "FOB",
  itar: false,
};
store.upsert(l0);
const id = l0.traveler_id;
const hash1 = travelerHash(store.get(id)!);
note(`level ${levelOf(l0).code} · hash ${short(hash1)}`);
assert.equal(levelOf(l0).code, "L0");

/* 2. A seller quotes — the quote binds to this exact revision's hash. */
step(2, "Summit Fabrication quotes — the quote binds to this exact revision");
const quote: Quote = {
  quote_id: newQuoteId(),
  seller: { org_id: "org_summitfab", name: "Summit Fabrication", certs: ["ISO 9001"] },
  traveler_hash_quoted: hash1,
  created_at: isoNow(),
  valid_until: "2030-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: { currency: "USD", nre: 35000, lines: [{ qty: 100, unit: 1850 }, { qty: 250, unit: 1420 }, { qty: 500, unit: 1175 }] },
};
store.addQuote(id, quote);
note(`level ${levelOf(store.get(id)!).code} · bound quotes ${boundQuotes(store.get(id)!).length}`);
assert.equal(levelOf(store.get(id)!).code, "L1");

/* 3. The buyer amends the spec — the hash moves and the quote goes stale. */
step(3, "Buyer amends the spec — the hash moves, so the quote goes stale");
store.amend(id, { incoterms: "EXW" });
const amended = store.get(id)!;
const hash2 = travelerHash(amended);
note(`hash ${short(hash1)} → ${short(hash2)} · bound ${boundQuotes(amended).length} · stale ${staleQuotes(amended).length} · level ${levelOf(amended).code}`);
assert.notEqual(hash1, hash2);
assert.equal(boundQuotes(amended).length, 0);
assert.equal(staleQuotes(amended).length, 1);

/* 4. A different shop quotes the amended spec, binding to the NEW hash. */
step(4, "Red River Machining quotes the amended spec (binds to the new hash)");
const quote2: Quote = {
  quote_id: newQuoteId(),
  seller: { org_id: "org_redriver", name: "Red River Machining", certs: ["ISO 9001", "AS9100"] },
  traveler_hash_quoted: hash2,
  created_at: isoNow(),
  valid_until: "2030-01-01T00:00:00.000Z",
  lead_time_days: 18,
  pricing: { currency: "USD", nre: 28000, lines: [{ qty: 100, unit: 1790 }, { qty: 250, unit: 1365 }, { qty: 500, unit: 1120 }] },
};
store.addQuote(id, quote2);
note(`level ${levelOf(store.get(id)!).code} · bound quotes ${boundQuotes(store.get(id)!).length}`);
assert.equal(levelOf(store.get(id)!).code, "L1");

/* 5. The buyer awards the bound quote with ops + ship-to → L2, and it locks. */
step(5, "Buyer awards the bound quote — traveler reaches L2 and locks");
store.award(
  id,
  { quote_id: quote2.quote_id, awarded_at: isoNow(), qty: 250 },
  { name: "Northline — Dock 4", line1: "1800 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" },
  [{ seq: 1, code: "laser" }, { seq: 2, code: "cnc-mill" }, { seq: 3, code: "deburr" }],
);
const awarded = store.get(id)!;
note(`level ${levelOf(awarded).code} · locked=${locked(awarded)} · quoteable hash ${short(travelerHash(awarded))}`);
assert.equal(levelOf(awarded).code, "L2");
assert.ok(locked(awarded));
assert.equal(travelerHash(awarded), hash2, "award leaves the quoteable hash unchanged");

/* 6. An executable (L2) traveler is immutable — amend is a no-op. */
step(6, "Amend-after-lock is refused");
const rev = awarded.revision;
store.amend(id, { incoterms: "FOB" });
assert.equal(store.get(id)!.revision, rev, "a locked traveler ignores amend");
note("the executable traveler is immutable — amend did nothing");

store.remove(id);
console.log("\n=== DONE — one quote bound to its exact revision; award locked at L2. ===");
