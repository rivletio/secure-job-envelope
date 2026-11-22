/** The desk's import action, end to end: the audit's attacks replayed against the store.
 *  (The policy's rules are tested one by one in import-policy.test.ts; this file checks
 *  that the store actually applies them — and stores nothing when it should not.) */
import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { quoteContentHash, signAward, signTraveler } from "./authenticity.ts";
import { levelOf, parseTraveler } from "./conformance.ts";
import type { Directory } from "./directory.ts";
import { travelerHash } from "./hash.ts";
import { keypairFromSeed } from "./signature.ts";
import { ImportNeedsAcknowledgment, useTravelerStore } from "./store.ts";
import type { Quote, Traveler } from "./types.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/signed-traveler.json", import.meta.url), "utf8"),
) as { root_public_key_hex: string; directory: Directory; traveler: Traveler };
const trust = { directory: vec.directory, rootPublicKeyHex: vec.root_public_key_hex };
const at = new Date("2027-01-01T00:00:00.000Z");
const northline = keypairFromSeed(new Uint8Array(32).fill(0x44));
const summit = keypairFromSeed(new Uint8Array(32).fill(0x33));

const rfq: Traveler = (() => {
  const { signatures: _omit, ...t } = parseTraveler(vec.traveler);
  void _omit;
  return t;
})();
const quoteFor = (t: Traveler, id: string, unit = 1500): Quote => ({
  quote_id: id,
  seller: { org_id: "org_summitfab", name: "Summit Fabrication", itar: true },
  traveler_hash_quoted: travelerHash(t),
  created_at: "2026-02-01T00:00:00.000Z",
  valid_until: "2028-01-01T00:00:00.000Z",
  lead_time_days: 14,
  pricing: { currency: "USD", lines: [{ qty: t.part.qty.target, unit }] },
});
const q1 = quoteFor(rfq, "qot_store00001");
const l1: Traveler = { ...rfq, quotes: [q1] };
const SHIP = { name: "Northline Dock 4", line1: "400 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" };
const awardOver = (t: Traveler, shipTo = SHIP): Traveler => ({
  ...t,
  award: { quote_id: q1.quote_id, quote_hash: quoteContentHash(q1), awarded_at: "2026-03-01T00:00:00.000Z", qty: t.part.qty.target },
  ship_to: shipTo,
  ops: [{ seq: 1, code: "laser" }],
});
const buyerSigned = (t: Traveler): Traveler => {
  const base = structuredClone(t);
  base.signatures = [signTraveler(base, "northline-2026", northline.secretKey)];
  if (base.award) base.award = { ...base.award, sig: signAward(base, "northline-2026", northline.secretKey) };
  return base;
};

const store = () => useTravelerStore.getState();
const held = () => store().get(rfq.traveler_id);
const importOne = (t: Traveler, acknowledged = false) => store().importOne(t, { trust, at, acknowledged });

describe("desk import: the audit's attacks, replayed", () => {
  beforeEach(() => {
    useTravelerStore.setState({ travelers: [], audit: [] });
  });

  it("a forged, unsigned award is not stored until the reader acknowledges it — and cannot lock the genuine one out", () => {
    importOne(l1); // the seller holds the RFQ with its own quote
    const forged = awardOver(l1, { ...SHIP, line1: "1 Attacker Way" });

    // Not stored, nothing audited: the reader has to be told first.
    assert.throws(
      () => importOne(forged),
      (e: unknown) => {
        assert.ok(e instanceof ImportNeedsAcknowledgment);
        assert.match(e.statements.join(" "), /not verified as the buyer's/);
        return true;
      },
    );
    assert.equal(held()?.award ?? null, null);
    assert.equal(levelOf(held()!).code, "L1");
    assert.equal(store().audit.filter((e) => e.act === "import").length, 1);

    // Suppose the reader is fooled and acknowledges it.
    importOne(forged, true);
    assert.equal(levelOf(held()!).code, "L2");
    assert.equal(held()?.ship_to?.line1, "1 Attacker Way");

    // The buyer's genuine, signed award still gets in — it used to be refused as "locked".
    const out = importOne(buyerSigned(awardOver(l1)));
    assert.equal(held()?.ship_to?.line1, SHIP.line1);
    assert.ok(held()?.award?.sig);
    assert.match(out.notes.join(" "), /never verified; the incoming award is verified as the buyer's/);

    // …and now the forged one is refused outright.
    assert.throws(() => importOne(forged, true), /verified as the buyer's and cannot be replaced/);
    assert.equal(held()?.ship_to?.line1, SHIP.line1);
  });

  it("an award signed by a bidder's real key is refused, whatever the reader acknowledges", () => {
    importOne(l1);
    const base = awardOver(l1, { ...SHIP, line1: "1 Attacker Way" });
    const bidderSigned = { ...base, award: { ...base.award!, sig: signAward(base, "summit-2026", summit.secretKey) } };
    assert.throws(() => importOne(bidderSigned, true), /award .* does not verify \(signer org does not match author org\)/);
    assert.equal(held()?.award ?? null, null);
  });

  it("a same-id copy no longer replaces what is held: rollback, body swap, quote wipe, ITAR strip", () => {
    const r2: Traveler = { ...rfq, revision: 2, part: { ...rfq.part, notes: "revision 2" } };
    const q2 = quoteFor(r2, "qot_store00002");
    importOne({ ...r2, quotes: [q2] });
    assert.equal(store().audit.length, 1);

    // rollback to the revision the stale quote was made against
    assert.throws(() => importOne(l1, true), /revision 1; revision 2 is already held/);
    // a different part under the same revision number
    assert.throws(
      () => importOne({ ...r2, part: { ...r2.part, notes: "swapped" } }, true),
      /same revision as the copy held, but its content is different/,
    );
    // a copy with no quotes does not wipe the held quote
    assert.equal(importOne(r2).kind, "unchanged");
    assert.deepEqual(held()?.quotes?.map((q) => q.quote_id), [q2.quote_id]);
    // nothing above stored or audited anything
    assert.equal(held()?.part.notes, "revision 2");
    assert.equal(store().audit.length, 2, "only the two admitted imports are audited");

    // stripping the ITAR flag
    useTravelerStore.setState({ travelers: [], audit: [] });
    importOne({ ...rfq, itar: true });
    assert.throws(() => importOne({ ...rfq, itar: false }, true), /content is different/);
    assert.equal(held()?.itar, true);
  });

  it("the buyer of a held traveler cannot be changed — even by an enrolled org signing as itself", () => {
    importOne(rfq);
    const body = { ...rfq, buyer: { ...rfq.buyer, org_id: "org_summitfab" } };
    const reissued = { ...body, signatures: [signTraveler(body, "summit-2026", summit.secretKey)] };
    assert.throws(() => importOne(reissued, true), /A traveler's buyer does not change/);
    assert.equal(held()?.buyer.org_id, "org_northline");
  });

  it("a merge that would exceed the schema's caps is refused, and the held copy is untouched", () => {
    const many = Array.from({ length: 40 }, (_, i) => quoteFor(rfq, `qot_storea${String(i).padStart(4, "0")}`));
    const more = Array.from({ length: 40 }, (_, i) => quoteFor(rfq, `qot_storeb${String(i).padStart(4, "0")}`));
    importOne({ ...rfq, quotes: many });
    assert.throws(() => importOne({ ...rfq, quotes: more }), /quotes: Too big/);
    assert.equal(held()?.quotes?.length, 40);
  });

  it("without a trust anchor nothing is verified — an award still needs acknowledgment", () => {
    store().importOne(l1);
    const signedAward = buyerSigned(awardOver(l1));
    assert.throws(() => store().importOne(signedAward), ImportNeedsAcknowledgment);
    assert.equal(store().importOne(signedAward, { acknowledged: true }).kind, "merged");
  });

  it("previewImport stores nothing", () => {
    const d = store().previewImport(awardOver(l1), { trust, at });
    assert.equal(d.action, "admit");
    assert.equal(store().travelers.length, 0);
    assert.equal(store().audit.length, 0);
  });
});
