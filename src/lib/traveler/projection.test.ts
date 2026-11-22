import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { quoteContentHash, signAward, signTraveler, verificationReport } from "./authenticity.ts";
import { levelOf, parseTraveler } from "./conformance.ts";
import type { Directory } from "./directory.ts";
import { travelerHash } from "./hash.ts";
import { projectForRecipient, withheldSummary } from "./projection.ts";
import { keypairFromSeed } from "./signature.ts";
import type { Quote, Traveler } from "./types.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/signed-traveler.json", import.meta.url), "utf8"),
) as { root_public_key_hex: string; directory: Directory; traveler: Traveler };
const northline = keypairFromSeed(new Uint8Array(32).fill(0x44));
const at = new Date("2027-01-01T00:00:00.000Z");

const rfq = parseTraveler(vec.traveler); // buyer org_northline, signed
const quote = (id: string, org: string | undefined, unit: number): Quote => ({
  quote_id: id,
  seller: { ...(org ? { org_id: org } : {}), name: `Seller ${id}` },
  traveler_hash_quoted: travelerHash(rfq),
  created_at: "2026-02-01T00:00:00.000Z",
  valid_until: "2028-01-01T00:00:00.000Z",
  lead_time_days: 14,
  pricing: { currency: "USD", lines: [{ qty: rfq.part.qty.target, unit }] },
});
const A = quote("qot_project001", "org_huron", 1500);
const B = quote("qot_project002", "org_summitfab", 1420);
const C = quote("qot_project003", undefined, 1300); // names no seller org
const withQuotes: Traveler = { ...rfq, quotes: [A, B, C] };
/** Awarded to org_summitfab (quote B), signed by the buyer. */
const awarded: Traveler = (() => {
  const t: Traveler = {
    ...withQuotes,
    award: { quote_id: B.quote_id, quote_hash: quoteContentHash(B), awarded_at: "2026-03-01T00:00:00.000Z", qty: rfq.part.qty.target },
    ship_to: { name: "Northline Dock 4", line1: "400 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" },
    ops: [{ seq: 1, code: "laser" }],
  };
  delete t.signatures;
  t.signatures = [signTraveler(t, "northline-2026", northline.secretKey)];
  t.award = { ...t.award!, sig: signAward(t, "northline-2026", northline.secretKey) };
  return t;
})();

const ids = (t: Traveler) => (t.quotes ?? []).map((q) => q.quote_id);
const verify = (t: Traveler) => verificationReport(t, vec.directory, vec.root_public_key_hex, at);

describe("per-recipient projection", () => {
  it("a seller receives the RFQ and only its own quote — never a competitor's price", () => {
    const p = projectForRecipient(withQuotes, "org_summitfab");
    assert.deepEqual(ids(p.traveler), [B.quote_id]);
    assert.deepEqual(p.withheld, { quotes: 2, award: false });
    assert.doesNotMatch(JSON.stringify(p.traveler), /1500|qot_project001|1300/, "no trace of the other bids");
    // a seller with no quote yet gets the bare RFQ
    const fresh = projectForRecipient(withQuotes, "org_redriver");
    assert.equal(fresh.traveler.quotes, undefined);
    assert.equal(fresh.withheld.quotes, 3);
  });

  it("the projection is still the same traveler: valid, same hash, same buyer signature", () => {
    const p = projectForRecipient(withQuotes, "org_summitfab");
    assert.doesNotThrow(() => parseTraveler(p.traveler));
    assert.equal(travelerHash(p.traveler), travelerHash(withQuotes));
    assert.equal(verify(p.traveler).authored, true);
    assert.equal(levelOf(p.traveler).code, "L1");
  });

  it("the winner receives the award with its own quote, and it still verifies", () => {
    const p = projectForRecipient(awarded, "org_summitfab");
    assert.deepEqual(ids(p.traveler), [B.quote_id]);
    assert.deepEqual(p.withheld, { quotes: 2, award: false });
    assert.equal(levelOf(p.traveler).code, "L2");
    const r = verify(p.traveler);
    assert.equal(r.award?.ok, true, r.award?.reason);
    assert.equal(r.verified, true);
  });

  it("a losing bidder learns neither who won nor where it ships", () => {
    const p = projectForRecipient(awarded, "org_huron");
    assert.deepEqual(ids(p.traveler), [A.quote_id]);
    assert.deepEqual(p.withheld, { quotes: 2, award: true });
    for (const member of ["award", "ship_to", "ops", "as_built"] as const) {
      assert.equal(p.traveler[member], undefined, member);
    }
    assert.doesNotMatch(JSON.stringify(p.traveler), /Industrial Way|qot_project002/);
    assert.doesNotThrow(() => parseTraveler(p.traveler));
    assert.equal(verify(p.traveler).authored, true);
  });

  it("the buyer receives everything", () => {
    const p = projectForRecipient(awarded, "org_northline");
    assert.equal(p.traveler, awarded);
    assert.deepEqual(p.withheld, { quotes: 0, award: false });
  });

  it("a sender's own quotes travel with it — a seller returning a quote, or an as-built record", () => {
    // The buyer wrote no org_id, so the recipient cannot be recognized as the buyer:
    // the seller's own quote (and an award over it) must still go back.
    const anon = structuredClone(awarded);
    delete anon.buyer.org_id;
    const back = projectForRecipient({ ...anon, as_built: { lot: "L-1" } }, "org_whoever", { senderOrg: "org_summitfab" });
    assert.deepEqual(ids(back.traveler), [B.quote_id]);
    assert.ok(back.traveler.award && back.traveler.as_built, "the award and as-built data go back with it");
    assert.deepEqual(back.withheld, { quotes: 2, award: false });
  });

  it("before an award, the buyer's draft ship-to and ops are left as the buyer put them", () => {
    const draft: Traveler = { ...withQuotes, ship_to: awarded.ship_to, ops: awarded.ops };
    const p = projectForRecipient(draft, "org_huron");
    assert.deepEqual(p.traveler.ship_to, awarded.ship_to);
    assert.deepEqual(p.traveler.ops, awarded.ops);
  });

  it("says what it left out in counts, and nothing when it left nothing out", () => {
    assert.equal(withheldSummary({ quotes: 0, award: false }), null);
    assert.equal(withheldSummary(projectForRecipient(awarded, "org_northline").withheld), null);
    assert.equal(withheldSummary({ quotes: 1, award: false }), "1 quote that is neither the recipient's nor yours");
    assert.equal(
      withheldSummary(projectForRecipient(awarded, "org_huron").withheld),
      "2 quotes that are neither the recipient's nor yours, and the award, with its ship-to, ops and as-built data",
    );
    assert.equal(withheldSummary({ quotes: 0, award: true }), "the award, with its ship-to, ops and as-built data");
  });

  it("never mutates what it was given", () => {
    const before = JSON.stringify(awarded);
    projectForRecipient(awarded, "org_huron");
    assert.equal(JSON.stringify(awarded), before);
  });
});
