import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { parseTraveler } from "./conformance.ts";
import {
  verifyTravelerSignatures,
  travelerIsAuthentic,
  signQuote,
  verifyQuoteSignature,
  itarAttestationBlocker,
} from "./authenticity.ts";
import { keypairFromSeed, hexToBytes } from "./signature.ts";
import type { Directory } from "./directory.ts";
import type { Traveler, Quote } from "./types.ts";

const vec = JSON.parse(
  readFileSync(
    new URL("../../../conformance/signatures/signed-traveler.json", import.meta.url),
    "utf8",
  ),
) as { root_public_key_hex: string; directory: Directory; traveler: Traveler };

const rootPk = vec.root_public_key_hex;
const dir = vec.directory;
const at = new Date("2027-01-01T00:00:00.000Z");

function quoteFor(orgId: string): Quote {
  return {
    quote_id: "qot_authtest1",
    seller: { org_id: orgId, name: "Seller", itar: true },
    traveler_hash_quoted: "sha384:" + "a".repeat(96),
    created_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2026-02-01T00:00:00.000Z",
    lead_time_days: 10,
    pricing: { currency: "USD", lines: [{ qty: 1, unit: 1000 }] },
  };
}

describe("traveler authenticity (end to end)", () => {
  it("verifies the buyer authorship signature via the directory", () => {
    const t = parseTraveler(vec.traveler);
    const checks = verifyTravelerSignatures(t, dir, rootPk, at);
    assert.equal(checks.length, 1);
    assert.equal(checks[0]!.ok, true);
    assert.equal(checks[0]!.org_id, "org_northline");
    assert.equal(travelerIsAuthentic(t, dir, rootPk, at), true);
  });

  it("rejects a tampered body, a wrong signer org, and a broken directory", () => {
    const t = parseTraveler(vec.traveler);
    assert.equal(travelerIsAuthentic({ ...t, revision: t.revision + 1 }, dir, rootPk, at), false);
    assert.equal(
      travelerIsAuthentic({ ...t, buyer: { ...t.buyer, org_id: "org_huron" } }, dir, rootPk, at),
      false,
    );
    assert.equal(travelerIsAuthentic(t, dir, "00".repeat(2592), at), false);
  });

  it("gates ITAR on the directory-attested capability, not seller self-declaration", () => {
    const base = parseTraveler(vec.traveler);
    const itarT: Traveler = { ...base, itar: true };
    // org_huron is ITAR-attested; org_summitfab is not
    assert.equal(itarAttestationBlocker(itarT, quoteFor("org_huron"), dir, at), null);
    assert.ok(itarAttestationBlocker(itarT, quoteFor("org_summitfab"), dir, at));
    // a non-ITAR traveler imposes no gate
    assert.equal(itarAttestationBlocker({ ...base, itar: false }, quoteFor("org_summitfab"), dir, at), null);
  });

  it("signs and verifies a seller quote signature against the directory", () => {
    // seed 0x22.. is org_huron's key (kid huron-2026) in the vector directory
    const kp = keypairFromSeed(hexToBytes("22".repeat(32)));
    const quote = quoteFor("org_huron");
    quote.sig = signQuote(quote, "huron-2026", kp.secretKey);
    const check = verifyQuoteSignature(quote, dir, rootPk, at);
    assert.equal(check?.ok, true);
    assert.equal(check?.org_id, "org_huron");
  });
});
