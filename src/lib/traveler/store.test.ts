/** State-machine tests for the desk store — these back the spec's claims:
 *  "amend bumps revision and stale-marks quotes", "L2 travelers lock",
 *  "every state change is audited". See docs/CLAIMS.md.
 */
import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import { readFileSync } from "node:fs";

// zustand/persist wants Storage; give node a minimal one BEFORE importing the store.
const mem = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
  clear: () => mem.clear(),
  key: (i: number) => [...mem.keys()][i] ?? null,
  get length() {
    return mem.size;
  },
};

const { useTravelerStore } = await import("./store.ts");
const { parseTraveler, levelOf, staleQuotes } = await import("./conformance.ts");
const { travelerHash } = await import("./hash.ts");
const { isoNow, randToken } = await import("./ids.ts");
import type { Traveler, Quote, ShipTo } from "./types.ts";

const root = new URL("../../../conformance/", import.meta.url).pathname;

function freshTraveler(): Traveler {
  const p = parseTraveler(
    JSON.parse(readFileSync(`${root}travelers/l0-bracket.json`, "utf8")),
  );
  return { ...p, traveler_id: `tvl_t${randToken(8)}`, quotes: [] };
}

function boundQuoteFor(p: Traveler): Quote {
  return {
    quote_id: `qot_t${randToken(8)}`,
    seller: { org_id: "org_summitfab", name: "Summit Fabrication" },
    traveler_hash_quoted: travelerHash(p),
    created_at: isoNow(),
    valid_until: "2039-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: { currency: "USD", lines: [{ qty: p.part.qty.target, unit: 14.2 }] },
  };
}

const SHIP: ShipTo = {
  name: "Northline Equipment — Dock 4",
  line1: "1800 Industrial Way",
  city: "Reno",
  region: "NV",
  postal: "89502",
  country: "US",
};

describe("desk store state machine", () => {
  beforeEach(() => useTravelerStore.getState().resetDesk());

  it("amend bumps revision and stale-marks every quote", () => {
    const s = useTravelerStore.getState();
    const p = freshTraveler();
    s.upsert(p);
    s.addQuote(p.traveler_id, boundQuoteFor(p));
    assert.equal(levelOf(useTravelerStore.getState().get(p.traveler_id)!).code, "L1");

    useTravelerStore.getState().amend(p.traveler_id, { need_by: "2026-12-01" });
    const amended = useTravelerStore.getState().get(p.traveler_id)!;
    assert.equal(amended.revision, p.revision + 1);
    assert.equal(staleQuotes(amended).length, 1, "old quote no longer binds");
    assert.equal(levelOf(amended).code, "L0", "stale quote drops traveler back to L0");
  });

  it("award requires a bound quote and locks the traveler at L2", () => {
    const s = useTravelerStore.getState();
    const p = freshTraveler();
    s.upsert(p);
    const q = boundQuoteFor(p);
    s.addQuote(p.traveler_id, q);
    s.award(
      p.traveler_id,
      { quote_id: q.quote_id, awarded_at: isoNow(), qty: p.part.qty.target },
      SHIP,
      [{ seq: 1, code: "laser" }],
    );
    const awarded = useTravelerStore.getState().get(p.traveler_id)!;
    assert.equal(levelOf(awarded).code, "L2");

    // the lock: amend after award is a no-op — revision and level unchanged
    useTravelerStore.getState().amend(p.traveler_id, { need_by: "2027-01-01" });
    const after = useTravelerStore.getState().get(p.traveler_id)!;
    assert.equal(after.revision, awarded.revision, "locked traveler does not amend");
    assert.equal(levelOf(after).code, "L2");
    assert.equal(after.need_by, awarded.need_by);
  });

  it("refuses to award a stale (unbound) quote", () => {
    const s = useTravelerStore.getState();
    const p = freshTraveler();
    s.upsert(p);
    const q = boundQuoteFor(p);
    s.addQuote(p.traveler_id, q);
    useTravelerStore.getState().amend(p.traveler_id, { incoterms: "EXW" });
    assert.throws(() =>
      useTravelerStore
        .getState()
        .award(p.traveler_id, { quote_id: q.quote_id, awarded_at: isoNow(), qty: 250 }, SHIP, [
          { seq: 1, code: "laser" },
        ]),
    );
  });

  it("audits every state change in order", () => {
    const s = useTravelerStore.getState();
    const p = freshTraveler();
    s.upsert(p);
    const q = boundQuoteFor(p);
    s.addQuote(p.traveler_id, q);
    useTravelerStore.getState().amend(p.traveler_id, { incoterms: "EXW" });
    const acts = useTravelerStore
      .getState()
      .audit.filter((e) => e.traveler_id === p.traveler_id)
      .map((e) => e.act);
    assert.deepEqual(acts, ["compose", "quote", "amend"]);
    for (const e of useTravelerStore.getState().audit) {
      assert.ok(e.at, "audit entries are timestamped");
    }
  });
});
