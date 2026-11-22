/** Rules the lifecycle review surfaced after the fact: a lapsed quote must not shut its
 *  seller out, an award's own quantity must be priced, and nothing persisted is trusted
 *  on the way back in — nor is a failed save allowed to be silent. */
import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { readFileSync } from "node:fs";

// A storage whose writes can be made to fail, installed BEFORE the store is imported.
const mem = new Map<string, string>();
let failWrites = false;
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => {
    if (failWrites) throw new Error("QuotaExceededError");
    mem.set(k, v);
  },
  removeItem: (k: string) => void mem.delete(k),
};
const events: string[] = [];
(globalThis as Record<string, unknown>).window = {
  dispatchEvent: (e: Event) => {
    events.push(e.type);
    return true;
  },
};

const { useTravelerStore, lastStorageWriteFailed, STORAGE_WRITE_FAILED, TRAVELER_STORE_KEY } = await import("./store.ts");
const { levelOf, parseTraveler } = await import("./conformance.ts");
const { cannotAward, cannotQuote } = await import("./guards.ts");
const { travelerHash } = await import("./hash.ts");
import type { Quote, Traveler } from "./types.ts";

const base = parseTraveler(
  JSON.parse(readFileSync(new URL("../../../conformance/travelers/l0-bracket.json", import.meta.url), "utf8")),
);
const rfq: Traveler = { ...base, traveler_id: "tvl_guards00001" };
const quote = (id: string, validUntil: string, lines = [{ qty: rfq.part.qty.target, unit: 1500 }]): Quote => ({
  quote_id: id,
  seller: { org_id: "org_summitfab", name: "Summit Fabrication" },
  traveler_hash_quoted: travelerHash(rfq),
  created_at: "2026-02-01T00:00:00.000Z",
  valid_until: validUntil,
  lead_time_days: 14,
  pricing: { currency: "USD", lines },
});
const SHIP = { name: "Dock 4", line1: "400 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" };
const store = () => useTravelerStore.getState();

describe("lifecycle follow-ups", () => {
  beforeEach(() => {
    failWrites = false;
    events.length = 0;
    useTravelerStore.setState({ travelers: [], audit: [] });
  });

  it("an expired quote does not hold its seller's slot on the revision", () => {
    const lapsed = quote("qot_guards0001", "2026-03-01T00:00:00.000Z");
    const fresh = quote("qot_guards0002", "2028-01-01T00:00:00.000Z");
    const held: Traveler = { ...rfq, quotes: [lapsed] };
    const whileLive = new Date("2026-02-15T00:00:00.000Z");
    const afterExpiry = new Date("2026-06-01T00:00:00.000Z");
    assert.match(cannotQuote(held, fresh, whileLive) ?? "", /already has a live quote on this revision/);
    assert.equal(cannotQuote(held, fresh, afterExpiry), null, "the lapsed quote can be replaced");
  });

  it("an award's own quantity must be one the quote prices", () => {
    const q = quote("qot_guards0003", "2039-01-01T00:00:00.000Z");
    store().upsert(rfq);
    store().addQuote(rfq.traveler_id, q);
    const award = (qty: number) =>
      store().award(rfq.traveler_id, { quote_id: q.quote_id, awarded_at: "2026-03-01T00:00:00.000Z", qty }, SHIP, [
        { seq: 1, code: "LASER" },
      ]);
    assert.throws(() => award(1_000_000), /no unit price at qty 1000000/);
    assert.equal(store().get(rfq.traveler_id)?.award ?? null, null, "nothing was stored");
    award(rfq.part.qty.target);
    assert.equal(store().get(rfq.traveler_id)?.award?.qty, rfq.part.qty.target);
  });

  it("the award guard asks about the quantity being awarded, not the target", () => {
    // A quote that prices a break quantity and not the target. Awarding the priced
    // quantity is sound — it is what a signed award must name to verify — and used to be
    // refused for want of a price at the target, which this award is not for.
    const breakQty = rfq.part.qty.target + 250;
    const q = quote("qot_guards0004", "2039-01-01T00:00:00.000Z", [{ qty: breakQty, unit: 1100 }]);
    store().upsert(rfq);
    store().addQuote(rfq.traveler_id, q);
    const held = store().get(rfq.traveler_id)!;
    const now = new Date("2026-03-01T00:00:00.000Z");
    assert.match(cannotAward(held, q, now) ?? "", new RegExp(`no unit price at qty ${rfq.part.qty.target}\\.`));
    assert.equal(cannotAward(held, q, now, breakQty), null);
    store().award(rfq.traveler_id, { quote_id: q.quote_id, awarded_at: "2026-03-01T00:00:00.000Z", qty: breakQty }, SHIP, [
      { seq: 1, code: "LASER" },
    ]);
    const awarded = store().get(rfq.traveler_id)!;
    assert.equal(awarded.award?.qty, breakQty);
    assert.equal(levelOf(awarded).code, "L2");
  });

  it("nothing persisted is spread into state unexamined", async () => {
    mem.set(
      TRAVELER_STORE_KEY,
      JSON.stringify({
        state: {
          role: "admin",
          sellerOrgId: { toString: "x" },
          travelers: [rfq, { not: "a traveler" }],
          audit: [{ at: 5 }],
          hydrated: true,
          award: "not a function",
          get: null,
        },
        version: 0,
      }),
    );
    await useTravelerStore.persist.rehydrate();
    const s = store();
    assert.ok(s.role === "buyer" || s.role === "seller", "an unknown role is not adopted");
    assert.equal(typeof s.sellerOrgId, "string");
    assert.ok(s.seller().org_id, "the seller still resolves to a shop");
    assert.deepEqual(s.travelers.map((t) => t.traveler_id), [rfq.traveler_id]);
    assert.deepEqual(s.audit, []);
    assert.equal(typeof s.award, "function", "an action is never replaced by stored data");
    assert.equal(typeof s.get, "function");
  });

  it("a failed save is announced, not swallowed", () => {
    store().upsert(rfq);
    assert.equal(lastStorageWriteFailed(), false);
    assert.equal(events.length, 0);
    failWrites = true;
    store().upsert({ ...rfq, traveler_id: "tvl_guards00002" });
    assert.equal(lastStorageWriteFailed(), true);
    assert.ok(events.includes(STORAGE_WRITE_FAILED), "the desk is told the write failed");
    assert.equal(store().travelers.length, 2, "the work is still in memory");
    // …and the flag clears once a write goes through again.
    failWrites = false;
    store().upsert({ ...rfq, traveler_id: "tvl_guards00003" });
    assert.equal(lastStorageWriteFailed(), false);
  });
});
