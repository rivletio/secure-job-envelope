import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { parseTraveler } from "./conformance.ts";
import {
  verifyAwardSignature,
  awardIsAuthentic,
  signAward,
  type SigCheck,
} from "./authenticity.ts";
import { keypairFromSeed } from "./signature.ts";
import type { Directory } from "./directory.ts";
import type { Traveler } from "./types.ts";

const vec = JSON.parse(
  readFileSync(
    new URL("../../../conformance/signatures/signed-award.json", import.meta.url),
    "utf8",
  ),
) as { root_public_key_hex: string; at_ms: number; directory: Directory; traveler: Traveler };

const rootPk = vec.root_public_key_hex;
const dir = vec.directory;
const at = new Date(vec.at_ms);
// Generator key seeds (conformance/generate.ts): the buyer org_northline is 0x44,
// and a losing bidder org_summitfab is 0x33.
const northline = keypairFromSeed(new Uint8Array(32).fill(0x44));
const summit = keypairFromSeed(new Uint8Array(32).fill(0x33));

describe("award authenticity (buyer signs the award + ship-to)", () => {
  it("verifies the buyer's award signature via the directory", () => {
    const t = parseTraveler(vec.traveler);
    const check = verifyAwardSignature(t, dir, rootPk, at);
    assert.equal(check?.ok, true);
    assert.equal(check?.org_id, "org_northline");
    assert.equal(awardIsAuthentic(t, dir, rootPk, at), true);
  });

  it("returns undefined when there is no award to check", () => {
    const t = parseTraveler(vec.traveler);
    assert.equal(verifyAwardSignature({ ...t, award: null }, dir, rootPk, at), undefined);
    assert.equal(awardIsAuthentic({ ...t, award: null }, dir, rootPk, at), false);
  });

  it("flags a present-but-unsigned award (fail closed, not a silent accept)", () => {
    const t = parseTraveler(vec.traveler);
    const unsigned: Traveler = { ...structuredClone(t), award: { ...t.award!, sig: undefined } };
    const check = verifyAwardSignature(unsigned, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check!.reason ?? "", /not signed/);
    assert.equal(awardIsAuthentic(unsigned, dir, rootPk, at), false);
  });

  it("refuses a forged award from a losing bidder (the BEC attack)", () => {
    // A losing bidder (org_summitfab) signs a self-serving award with THEIR own key
    // and kid. They cannot produce a buyer-org signature, so the winner refuses it.
    const forged: Traveler = structuredClone(parseTraveler(vec.traveler));
    forged.award = { ...forged.award!, qty: 1 };
    forged.award.sig = signAward(forged, "summit-2026", summit.secretKey);
    const check = verifyAwardSignature(forged, dir, rootPk, at);
    assert.equal(check?.ok, false); // signer org (summitfab) != buyer org (northline)
    assert.equal(awardIsAuthentic(forged, dir, rootPk, at), false);
  });

  it("refuses a bidder who claims the buyer's kid but signs with their own key", () => {
    const forged: Traveler = structuredClone(parseTraveler(vec.traveler));
    // Label it with the buyer's kid, but sign with summit's key: the kid resolves to
    // northline's public key, under which summit's signature does not verify.
    forged.award = { ...forged.award!, sig: signAward(forged, "northline-2026", summit.secretKey) };
    assert.equal(verifyAwardSignature(forged, dir, rootPk, at)?.ok, false);
  });

  it("breaks the award signature when the ship-to is altered", () => {
    const t = parseTraveler(vec.traveler);
    const altered: Traveler = { ...structuredClone(t), ship_to: { ...t.ship_to!, postal: "00000" } };
    assert.equal(verifyAwardSignature(altered, dir, rootPk, at)?.ok, false);
  });

  it("breaks the award signature when the awarded qty or the revision changes", () => {
    const t = parseTraveler(vec.traveler);
    const reqty: Traveler = { ...structuredClone(t), award: { ...t.award!, qty: t.award!.qty + 1 } };
    assert.equal(verifyAwardSignature(reqty, dir, rootPk, at)?.ok, false);
    const rev: Traveler = { ...structuredClone(t), revision: t.revision + 1 };
    assert.equal(verifyAwardSignature(rev, dir, rootPk, at)?.ok, false);
  });

  it("re-signs and verifies with the buyer key (round-trip)", () => {
    const t = parseTraveler(vec.traveler);
    const fresh: Traveler = { ...structuredClone(t), award: { ...t.award!, qty: 500 } };
    fresh.award!.sig = signAward(fresh, "northline-2026", northline.secretKey);
    assert.equal(verifyAwardSignature(fresh, dir, rootPk, at)?.ok, true);
  });

  it("fails closed on a non-canonicalizable body, never throws", () => {
    const t = parseTraveler(vec.traveler);
    // A hostile thickness makes the quoteable body (hence travelerHash, hence the
    // award body) uncanonicalizable; verification must return ok:false, not throw.
    const bad = {
      ...structuredClone(t),
      part: { ...t.part, material: { spec: "6061-T6", thickness_mm: 1e308 } },
      award: { ...t.award!, sig: { alg: "ML-DSA-87", kid: "northline-2026", sig: "ab" } },
    } as Traveler;
    let check: SigCheck | undefined;
    assert.doesNotThrow(() => {
      check = verifyAwardSignature(bad, dir, rootPk, at);
    });
    assert.equal(check?.ok, false);
  });

  it("refuses the award against a directory that does not verify against the root", () => {
    const t = parseTraveler(vec.traveler);
    assert.equal(verifyAwardSignature(t, dir, "00".repeat(2592), at)?.ok, false);
  });

  it("binds the awarded quote's priced content — a swapped unit price is refused (completeness)", () => {
    // The awarded quote (qot_conform01) is present and UNSIGNED — the exact gap case. Swapping
    // its unit price leaves the buyer's award signature valid over the body, but the quote no
    // longer hashes to the buyer-signed award.quote_hash, so the award is refused.
    const t = parseTraveler(vec.traveler);
    const swapped = structuredClone(t);
    const q = swapped.quotes!.find((x) => x.quote_id === swapped.award!.quote_id)!;
    q.pricing.lines[0].unit = q.pricing.lines[0].unit + 1;
    const check = verifyAwardSignature(swapped, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /quote content does not match|quote_hash/);
    assert.equal(awardIsAuthentic(swapped, dir, rootPk, at), false);
  });

  it("hard-fails when the awarded quote is stripped from the traveler", () => {
    // A stripped awarded quote leaves nothing to re-verify the priced content against.
    const t = parseTraveler(vec.traveler);
    const stripped: Traveler = { ...structuredClone(t), quotes: [] };
    const check = verifyAwardSignature(stripped, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /not present/);
  });

  it("refuses a signed award whose quote_hash was tampered (it is inside the signed body)", () => {
    const t = parseTraveler(vec.traveler);
    const tampered = structuredClone(t);
    tampered.award!.quote_hash = "sha384:" + "0".repeat(96);
    // quote_hash rides inside the signed award body, so changing it breaks the buyer signature.
    assert.equal(verifyAwardSignature(tampered, dir, rootPk, at)?.ok, false);
  });
});
