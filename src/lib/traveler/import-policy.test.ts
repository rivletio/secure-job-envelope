/** The receive policy, one rule per test. Signatures here are real (ML-DSA-87 against
 *  the conformance directory), so "verified", "unverified" and "invalid" are what the
 *  verifier actually reports, not stubs. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  quoteContentHash,
  signAward,
  signQuote,
  signTraveler,
  verificationReport,
} from "./authenticity.ts";
import { levelOf, parseTraveler } from "./conformance.ts";
import type { Directory } from "./directory.ts";
import { travelerHash } from "./hash.ts";
import { decideImport, type ImportDecision } from "./import-policy.ts";
import { keypairFromSeed } from "./signature.ts";
import type { Quote, Traveler } from "./types.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/signed-traveler.json", import.meta.url), "utf8"),
) as { root_public_key_hex: string; directory: Directory; traveler: Traveler };
const dir = vec.directory;
const rootPk = vec.root_public_key_hex;
const at = new Date("2027-01-01T00:00:00.000Z");
const northline = keypairFromSeed(new Uint8Array(32).fill(0x44)); // the buyer
const summit = keypairFromSeed(new Uint8Array(32).fill(0x33)); // an enrolled bidder
const huron = keypairFromSeed(new Uint8Array(32).fill(0x22));

const report = (t: Traveler) => verificationReport(t, dir, rootPk, at);
/** Decide with real verification of both copies. */
const decide = (incoming: Traveler, held?: Traveler): ImportDecision =>
  decideImport(incoming, {
    held,
    incomingReport: report(incoming),
    heldReport: held ? report(held) : undefined,
  });
const admitted = (d: ImportDecision) => {
  assert.equal(d.action, "admit", d.action === "refuse" ? d.reason : "");
  if (d.action !== "admit") throw new Error("unreachable");
  parseTraveler(d.traveler); // every admitted result is a valid traveler
  return d;
};
const refused = (d: ImportDecision, why: RegExp) => {
  assert.equal(d.action, "refuse");
  if (d.action === "refuse") assert.match(d.reason, why);
};

// ---- fixtures ----
const unsigned = (t: Traveler): Traveler => {
  const { signatures: _omit, ...rest } = structuredClone(t);
  void _omit;
  return rest;
};
const signedByBuyer = (t: Traveler): Traveler => {
  const body = unsigned(t);
  return { ...body, signatures: [signTraveler(body, "northline-2026", northline.secretKey)] };
};
const rfq: Traveler = unsigned(parseTraveler(vec.traveler)); // L0, buyer org_northline
const quoteFor = (t: Traveler, id: string, org = "org_summitfab", unit = 1500): Quote => ({
  quote_id: id,
  seller: { org_id: org, name: "Seller", itar: true },
  traveler_hash_quoted: travelerHash(t),
  created_at: "2026-02-01T00:00:00.000Z",
  valid_until: "2028-01-01T00:00:00.000Z",
  lead_time_days: 14,
  pricing: { currency: "USD", lines: [{ qty: t.part.qty.target, unit }] },
});
const withQuotes = (t: Traveler, ...quotes: Quote[]): Traveler => ({ ...t, quotes: [...(t.quotes ?? []), ...quotes] });
const SHIP = { name: "Northline Dock 4", line1: "400 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" };
/** An award over `quoteId`, unsigned (what the shipped desk produces). */
const awarded = (t: Traveler, quoteId: string, shipTo = SHIP): Traveler => {
  const q = t.quotes!.find((x) => x.quote_id === quoteId)!;
  return {
    ...t,
    award: { quote_id: quoteId, quote_hash: quoteContentHash(q), awarded_at: "2026-03-01T00:00:00.000Z", qty: t.part.qty.target },
    ship_to: shipTo,
    ops: [{ seq: 1, code: "laser" }],
  };
};
const awardSignedBy = (t: Traveler, kid: string, secretKey: Uint8Array): Traveler => {
  const base = structuredClone(t);
  delete base.award!.sig;
  return { ...base, award: { ...base.award!, sig: signAward(base, kid, secretKey) } };
};
const amended = (t: Traveler, notes: string): Traveler => ({
  ...unsigned(t),
  revision: t.revision + 1,
  part: { ...t.part, notes },
  quotes: undefined,
  award: null,
  ship_to: null,
  ops: undefined,
});

const q1 = quoteFor(rfq, "qot_policy0001");
const l1 = withQuotes(rfq, q1);

describe("receive policy: a traveler not held before", () => {
  it("admits an unsigned RFQ, saying that nothing shows who wrote it", () => {
    const d = admitted(decide(rfq));
    assert.equal(d.kind, "new");
    assert.deepEqual(d.acknowledge, []);
    assert.match(d.notes.join(" "), /Authorship is not verified/);
  });

  it("names the org that signed, from the directory — not the name the document carries", () => {
    const d = admitted(decide(signedByBuyer(rfq)));
    assert.match(d.notes.join(" "), /Signed by org_northline \(key northline-2026\)/);
    assert.deepEqual(d.acknowledge, []);
  });

  it("refuses a traveler whose buyer signature is present and fails", () => {
    const tampered = { ...signedByBuyer(rfq), part: { ...rfq.part, notes: "altered after signing" } };
    refused(decide(tampered), /buyer signature .* does not verify \(signature does not verify\)/);
    // the buyer's exact body, signed with ANOTHER enrolled org's real key
    const wrongOrg = { ...rfq, signatures: [signTraveler(rfq, "summit-2026", summit.secretKey)] };
    refused(decide(wrongOrg), /signer org does not match author org/);
  });

  it("treats a signature it cannot check as unverified, not as forged", () => {
    const unknownKid = { ...rfq, signatures: [{ ...signedByBuyer(rfq).signatures![0]!, kid: "nobody-2026" }] };
    assert.match(admitted(decide(unknownKid)).notes.join(" "), /Authorship is not verified/);
    // no trust anchor at all: nothing can be verified
    assert.match(admitted(decideImport(signedByBuyer(rfq))).notes.join(" "), /Authorship is not verified/);
  });

  it("admits an unsigned award only with an explicit acknowledgment", () => {
    const d = admitted(decide(awarded(l1, q1.quote_id)));
    assert.equal(d.acknowledge.length, 1);
    assert.match(d.acknowledge[0]!, /not verified as the buyer's.*ship-to address/s);
    // …and likewise when there is no trust anchor to check a signed award against
    const signedAward = awardSignedBy(awarded(l1, q1.quote_id), "northline-2026", northline.secretKey);
    assert.equal(admitted(decideImport(signedAward)).acknowledge.length, 1);
  });

  it("admits a buyer-signed award without asking", () => {
    const d = admitted(decide(awardSignedBy(awarded(l1, q1.quote_id), "northline-2026", northline.secretKey)));
    assert.deepEqual(d.acknowledge, []);
    assert.match(d.notes.join(" "), /Award verified as the buyer's/);
  });

  it("refuses an award that is signed and fails — a bidder's signature, a redirected ship-to", () => {
    const base = awarded(l1, q1.quote_id);
    refused(decide(awardSignedBy(base, "summit-2026", summit.secretKey)), /award .* does not verify \(signer org does not match author org\)/);
    const genuine = awardSignedBy(base, "northline-2026", northline.secretKey);
    refused(decide({ ...genuine, ship_to: { ...SHIP, line1: "1 Elsewhere Road" } }), /award .* does not verify \(signature does not verify\)/);
    // a genuine signature over an award whose quote was swapped afterwards
    const swapped = structuredClone(genuine);
    swapped.quotes![0]!.pricing.lines[0]!.unit = 1;
    refused(decide(swapped), /does not match the buyer-signed quote_hash/);
  });
});

describe("receive policy: a traveler already held", () => {
  it("buyer: refuses a copy that names a different buyer org", () => {
    const other = { ...rfq, buyer: { ...rfq.buyer, org_id: "org_summitfab" } };
    refused(decide(other, rfq), /held here as buyer org_northline; the incoming copy names org_summitfab/);
    const none = structuredClone(rfq);
    delete none.buyer.org_id;
    refused(decide(none, rfq), /incoming copy names no org_id/);
    refused(decide(rfq, none), /held here as buyer no org_id/);
    // even when the other org signs it with its own real key (it verifies — as that org)
    const reissued = { ...other, signatures: [signTraveler(other, "summit-2026", summit.secretKey)] };
    assert.equal(report(reissued).authored, true);
    refused(decide(reissued, rfq), /A traveler's buyer does not change/);
  });

  it("rollback: refuses an older revision", () => {
    const r2 = amended(rfq, "r2");
    refused(decide(rfq, r2), /This is revision 1; revision 2 is already held/);
  });

  it("equivocate: refuses the same revision with different content", () => {
    const swapped = { ...rfq, part: { ...rfq.part, notes: "a different part under the same revision number" } };
    refused(decide(swapped, rfq), /same revision as the copy held, but its content is different/);
    // stripping the ITAR flag is a content change like any other
    const itar = { ...rfq, itar: true };
    refused(decide({ ...itar, itar: false }, itar), /content is different/);
  });

  it("merge: adds the incoming copy's quotes and never drops or alters a held one", () => {
    const q2 = quoteFor(rfq, "qot_policy0002", "org_huron", 1400);
    const d = admitted(decide(withQuotes(rfq, q2), l1));
    assert.equal(d.kind, "merged");
    assert.deepEqual(d.traveler.quotes?.map((q) => q.quote_id), [q1.quote_id, q2.quote_id]);
    assert.deepEqual(d.acknowledge, []);
    // an incoming copy with NO quotes does not wipe the ones held
    const none = admitted(decide(rfq, l1));
    assert.equal(none.kind, "unchanged");
    assert.deepEqual(none.traveler.quotes, l1.quotes);
    // the held object itself is never mutated
    assert.equal(l1.quotes?.length, 1);
  });

  it("merge: refuses a quote that differs from the held quote with the same id", () => {
    const cheaper = { ...q1, pricing: { ...q1.pricing, lines: [{ qty: rfq.part.qty.target, unit: 1 }] } };
    refused(decide(withQuotes(rfq, cheaper), l1), /Quote qot_policy0001 differs from the copy of that quote held here/);
  });

  it("merge: takes a seller's signature for a quote held unsigned, when the content is identical", () => {
    const hq = quoteFor(rfq, "qot_policy0003", "org_huron");
    const signed = { ...hq, sig: signQuote(hq, "huron-2026", huron.secretKey) };
    const d = admitted(decide(withQuotes(rfq, signed), withQuotes(rfq, hq)));
    assert.equal(d.kind, "merged");
    assert.ok(d.traveler.quotes?.[0]?.sig, "the signed copy is kept");
  });

  it("award gate: an unsigned award over a held traveler needs acknowledgment, and brings its ship-to and ops", () => {
    const d = admitted(decide(awarded(l1, q1.quote_id), l1));
    assert.equal(d.kind, "merged");
    assert.equal(d.acknowledge.length, 1);
    assert.equal(levelOf(d.traveler).code, "L2");
    assert.deepEqual(d.traveler.ship_to, SHIP);
  });

  it("award: a verified held award is immovable", () => {
    const held = awardSignedBy(awarded(l1, q1.quote_id), "northline-2026", northline.secretKey);
    const elsewhere = awarded(l1, q1.quote_id, { ...SHIP, line1: "1 Elsewhere Road" });
    refused(decide(elsewhere, held), /verified as the buyer's and cannot be replaced/);
    // and an incoming copy WITHOUT an award does not remove it
    const d = admitted(decide(l1, held));
    assert.ok(d.traveler.award?.sig);
    assert.match(d.notes.join(" "), /carries no award; the award held here was kept/);
  });

  it("award: an unverified held award yields to a verified one — a forged award cannot lock the genuine one out", () => {
    // The attack: a forged, unsigned award with the attacker's ship-to arrives first and
    // is (mistakenly) acknowledged. The buyer's genuine, signed award must still get in.
    const forged = awarded(l1, q1.quote_id, { ...SHIP, line1: "1 Attacker Way" });
    const genuine = awardSignedBy(awarded(l1, q1.quote_id), "northline-2026", northline.secretKey);
    assert.equal(levelOf(forged).code, "L2", "the forged copy is 'executable'");
    const d = admitted(decide(genuine, forged));
    assert.deepEqual(d.traveler.ship_to, SHIP);
    assert.ok(d.traveler.award?.sig);
    assert.deepEqual(d.acknowledge, []);
    assert.match(d.notes.join(" "), /never verified; the incoming award is verified as the buyer's and replaces it/);
  });

  it("award: two different unverified awards cannot be told apart, so the held one stays", () => {
    const a = awarded(l1, q1.quote_id);
    const b = awarded(l1, q1.quote_id, { ...SHIP, line1: "1 Elsewhere Road" });
    refused(decide(b, a), /neither is verified as the buyer's/);
    assert.equal(admitted(decide(a, a)).kind, "unchanged");
  });

  it("floor: content verified as the buyer's is never replaced by content that is not", () => {
    const held = signedByBuyer(rfq);
    refused(decide(amended(rfq, "r2, unsigned"), held), /signed by its buyer.*not verified as the buyer's/s);
    // the buyer's own signed amendment is accepted
    const d = admitted(decide(signedByBuyer(amended(rfq, "r2, signed")), held));
    assert.equal(d.kind, "amended");
    assert.equal(d.traveler.revision, 2);
    assert.deepEqual(d.acknowledge, []);
  });

  it("amend: an unverified newer revision needs acknowledgment, and the held quotes are kept as history", () => {
    const r2 = amended(rfq, "r2, unsigned");
    const d = admitted(decide(r2, l1));
    assert.equal(d.kind, "amended");
    assert.match(d.acknowledge[0] ?? "", /replaces revision 1 of the part with revision 2, and nothing shows the change came from the buyer/);
    assert.equal(d.traveler.part.notes, "r2, unsigned");
    assert.deepEqual(d.traveler.quotes?.map((q) => q.quote_id), [q1.quote_id], "the held quote is kept");
    assert.equal(levelOf(d.traveler).code, "L0", "…but it no longer binds");
    assert.match(d.notes.join(" "), /1 quote held for revision 1 kept as history/);
  });

  it("amend: refused over an executable traveler — unless its lock is unverified and the amendment is the buyer's", () => {
    const verifiedLock = awardSignedBy(awarded(signedWithQuote(), q1s().quote_id), "northline-2026", northline.secretKey);
    refused(decide(signedByBuyer(amended(rfq, "r2")), verifiedLock), /executable under an award verified as the buyer's/);

    const unverifiedLock = awarded(l1, q1.quote_id);
    refused(decide(amended(rfq, "r2, unsigned"), unverifiedLock), /accepted over it only when that revision is verified as the buyer's/);
    const d = admitted(decide(signedByBuyer(amended(rfq, "r2, signed")), unverifiedLock));
    assert.equal(d.traveler.revision, 2);
    assert.match(d.notes.join(" "), /that award was never verified/);
  });

  it("amend: quotes an ITAR revision cannot carry are dropped, and said so", () => {
    const plainSeller: Quote = { ...quoteFor(rfq, "qot_policy0004"), seller: { org_id: "org_summitfab", name: "Seller" } };
    const held = withQuotes(rfq, q1, plainSeller);
    const d = admitted(decide({ ...amended(rfq, "now ITAR"), itar: true }, held));
    assert.deepEqual(d.traveler.quotes?.map((q) => q.quote_id), [q1.quote_id]);
    assert.match(d.notes.join(" "), /1 held quote from a seller without an ITAR declaration could not be kept/);
  });
});

// A signed L1 for the verified-lock case (the award must sit on a buyer-signed body).
function q1s(): Quote {
  return quoteFor(rfq, "qot_policy0005");
}
function signedWithQuote(): Traveler {
  return withQuotes(signedByBuyer(rfq), q1s());
}
