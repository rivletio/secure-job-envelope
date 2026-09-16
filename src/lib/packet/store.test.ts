/** State-machine tests for the desk store — these back the spec's claims:
 *  "amend bumps revision and stale-marks quotes", "L2 packets lock",
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

const { usePacketStore } = await import("./store.ts");
const { parsePacket, levelOf, staleQuotes } = await import("./conformance.ts");
const { packetHash } = await import("./hash.ts");
const { isoNow, randToken } = await import("./ids.ts");
import type { Packet, Quote, ShipTo } from "./types.ts";

const root = new URL("../../../conformance/", import.meta.url).pathname;

function freshPacket(): Packet {
  const p = parsePacket(
    JSON.parse(readFileSync(`${root}packets/l0-bracket.json`, "utf8")),
  );
  return { ...p, packet_id: `pkt_t${randToken(8)}`, quotes: [] };
}

function boundQuoteFor(p: Packet): Quote {
  return {
    quote_id: `qot_t${randToken(8)}`,
    seller: { org_id: "org_summitfab", name: "Summit Fabrication" },
    packet_hash_quoted: packetHash(p),
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
  beforeEach(() => usePacketStore.getState().resetDesk());

  it("amend bumps revision and stale-marks every quote", () => {
    const s = usePacketStore.getState();
    const p = freshPacket();
    s.upsert(p);
    s.addQuote(p.packet_id, boundQuoteFor(p));
    assert.equal(levelOf(usePacketStore.getState().get(p.packet_id)!).code, "L1");

    usePacketStore.getState().amend(p.packet_id, { need_by: "2026-12-01" });
    const amended = usePacketStore.getState().get(p.packet_id)!;
    assert.equal(amended.revision, p.revision + 1);
    assert.equal(staleQuotes(amended).length, 1, "old quote no longer binds");
    assert.equal(levelOf(amended).code, "L0", "stale quote drops packet back to L0");
  });

  it("award requires a bound quote and locks the packet at L2", () => {
    const s = usePacketStore.getState();
    const p = freshPacket();
    s.upsert(p);
    const q = boundQuoteFor(p);
    s.addQuote(p.packet_id, q);
    s.award(
      p.packet_id,
      { quote_id: q.quote_id, awarded_at: isoNow(), qty: p.part.qty.target },
      SHIP,
      [{ seq: 1, code: "laser" }],
    );
    const awarded = usePacketStore.getState().get(p.packet_id)!;
    assert.equal(levelOf(awarded).code, "L2");

    // the lock: amend after award is a no-op — revision and level unchanged
    usePacketStore.getState().amend(p.packet_id, { need_by: "2027-01-01" });
    const after = usePacketStore.getState().get(p.packet_id)!;
    assert.equal(after.revision, awarded.revision, "locked packet does not amend");
    assert.equal(levelOf(after).code, "L2");
    assert.equal(after.need_by, awarded.need_by);
  });

  it("refuses to award a stale (unbound) quote", () => {
    const s = usePacketStore.getState();
    const p = freshPacket();
    s.upsert(p);
    const q = boundQuoteFor(p);
    s.addQuote(p.packet_id, q);
    usePacketStore.getState().amend(p.packet_id, { incoterms: "EXW" });
    assert.throws(() =>
      usePacketStore
        .getState()
        .award(p.packet_id, { quote_id: q.quote_id, awarded_at: isoNow(), qty: 250 }, SHIP, [
          { seq: 1, code: "laser" },
        ]),
    );
  });

  it("audits every state change in order", () => {
    const s = usePacketStore.getState();
    const p = freshPacket();
    s.upsert(p);
    const q = boundQuoteFor(p);
    s.addQuote(p.packet_id, q);
    usePacketStore.getState().amend(p.packet_id, { incoterms: "EXW" });
    const acts = usePacketStore
      .getState()
      .audit.filter((e) => e.packet_id === p.packet_id)
      .map((e) => e.act);
    assert.deepEqual(acts, ["compose", "quote", "amend"]);
    for (const e of usePacketStore.getState().audit) {
      assert.ok(e.at, "audit entries are timestamped");
    }
  });
});
