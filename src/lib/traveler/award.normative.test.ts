import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { parseTraveler } from "./conformance.ts";
import {
  verifyAwardSignature,
  awardIsAuthentic,
  signAward,
  awardSignatureBody,
  type SigCheck,
} from "./authenticity.ts";
import { keypairFromSeed, signBody, SIG_ALG, SIG_DOMAIN } from "./signature.ts";
import type { Directory } from "./directory.ts";
import type { Traveler, Signature } from "./types.ts";

/**
 * NORMATIVE conformance tests for the buyer AWARD signature (SJE 0.1,
 * domain `sje-sig/award/0.1.0`). Each `it` asserts ONE normative requirement —
 * phrased as the MUST/SHALL it pins — so the award's security contract is an
 * explicit, auditable checklist, not only a set of behavioural cases. The
 * cross-language half (both implementations MUST agree) is pinned by the Rust
 * vector test `crates/secure-job-envelope/tests/vectors.rs::
 * signed_award_vector_verifies_cross_language`; these are the TS-side MUSTs.
 * Maps to docs/CLAIMS.md PQ11 and the F1 fix (the business-email-compromise
 * defence: a non-buyer MUST NOT be able to forge an award or redirect ship-to).
 *
 *   AW-1  A correctly buyer-signed award MUST verify, over exactly
 *         {spec, traveler_id, traveler_hash, award(−sig), ship_to}.
 *   AW-2  The directory MUST verify against the configured trust root, else refuse.
 *   AW-3  The signer's directory org MUST equal buyer.org_id (no non-buyer award).
 *   AW-4  A kid that names the buyer but a signature made with another key MUST fail.
 *   AW-5  The signature MUST bind ship_to (any change invalidates it).
 *   AW-6  The signature MUST bind the award decision (quote_id/qty/awarded_at/terms).
 *   AW-7  The signature MUST bind the exact revision via traveler_hash.
 *   AW-8  A present-but-unsigned award MUST be an authenticity FAILURE (fail closed).
 *   AW-9  An award signature declaring an unsupported alg MUST be refused.
 *   AW-10 A non-canonicalizable body MUST return "not verified", never throw.
 *   AW-11 The award domain MUST be distinct — a signature over the same bytes under
 *         another domain MUST NOT verify as an award (no cross-context replay).
 *   AW-12 A traveler with no award yields "nothing to verify" (undefined), which is
 *         distinct from an authenticity failure.
 *   AW-13 The signature MUST bind the awarded quote's priced content via `quote_hash`: a swapped
 *         unit price on the awarded quote (even an unsigned quote) MUST fail — completeness beyond
 *         the BEC core, closing the absent/unsigned-quote gap.
 *   AW-14 The awarded quote MUST be present to verify — a stripped awarded quote is a hard failure.
 *   AW-15 A signed award MUST carry a `quote_hash` — an award signed without one is refused.
 */

const vec = JSON.parse(
  readFileSync(
    new URL("../../../conformance/signatures/signed-award.json", import.meta.url),
    "utf8",
  ),
) as { root_public_key_hex: string; at_ms: number; directory: Directory; traveler: Traveler };

const rootPk = vec.root_public_key_hex;
const dir = vec.directory;
const at = new Date(vec.at_ms);
// Generator key seeds (conformance/generate.ts): buyer org_northline = 0x44,
// a losing bidder org_summitfab = 0x33.
const northline = keypairFromSeed(new Uint8Array(32).fill(0x44));
const summit = keypairFromSeed(new Uint8Array(32).fill(0x33));
const base = (): Traveler => parseTraveler(vec.traveler);

describe("award signature — normative requirements (SHALL)", () => {
  it("AW-1 (MUST): a correctly buyer-signed award verifies over exactly {spec, traveler_id, traveler_hash, award(−sig), ship_to}", () => {
    const t = base();
    const check = verifyAwardSignature(t, dir, rootPk, at);
    assert.equal(check?.ok, true);
    assert.equal(check?.org_id, "org_northline");
    assert.equal(awardIsAuthentic(t, dir, rootPk, at), true);
    // The signed body is exactly the normative field set (canonical → sorted keys),
    // and the award is included without its own signature.
    const body = JSON.parse(awardSignatureBody(t)) as Record<string, unknown>;
    assert.deepEqual(Object.keys(body), ["award", "ship_to", "spec", "traveler_hash", "traveler_id"]);
    assert.equal(Object.prototype.hasOwnProperty.call(body.award as object, "sig"), false);
  });

  it("AW-2 (MUST): the directory must verify against the configured trust root, else the award is refused", () => {
    assert.equal(verifyAwardSignature(base(), dir, "00".repeat(2592), at)?.ok, false);
  });

  it("AW-3 (MUST): the signer's directory org must equal buyer.org_id — a losing bidder's award is refused", () => {
    // A losing bidder (org_summitfab) signs a self-serving award with their own key/kid.
    const forged = base();
    forged.award = { ...forged.award!, qty: 1 };
    forged.award.sig = signAward(forged, "summit-2026", summit.secretKey);
    const check = verifyAwardSignature(forged, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /signer org does not match/);
    assert.equal(awardIsAuthentic(forged, dir, rootPk, at), false);
  });

  it("AW-4 (MUST): a kid that names the buyer but a signature made with another key is refused", () => {
    const forged = base();
    // Label with the buyer's kid, but sign with summit's key: the kid resolves to
    // northline's public key, under which summit's signature does not verify.
    forged.award = { ...forged.award!, sig: signAward(forged, "northline-2026", summit.secretKey) };
    assert.equal(verifyAwardSignature(forged, dir, rootPk, at)?.ok, false);
  });

  it("AW-5 (MUST): the signature binds ship_to — any change invalidates it", () => {
    const redirected = base();
    redirected.ship_to = { ...redirected.ship_to!, line1: "999 Attacker Rd", postal: "00000" };
    assert.equal(verifyAwardSignature(redirected, dir, rootPk, at)?.ok, false);
  });

  it("AW-6 (MUST): the signature binds the award decision (quote_id/qty/awarded_at/terms)", () => {
    const reqty = base();
    reqty.award = { ...reqty.award!, qty: reqty.award!.qty + 1 };
    assert.equal(verifyAwardSignature(reqty, dir, rootPk, at)?.ok, false);

    const requote = base();
    requote.award = { ...requote.award!, quote_id: "qot_somethingelse" };
    assert.equal(verifyAwardSignature(requote, dir, rootPk, at)?.ok, false);

    const reterms = base();
    reterms.award = { ...reterms.award!, terms: { ...reterms.award!.terms, payment_terms: "Net 90" } };
    assert.equal(verifyAwardSignature(reterms, dir, rootPk, at)?.ok, false);
  });

  it("AW-7 (MUST): the signature binds the exact revision via traveler_hash", () => {
    const rev = base();
    rev.revision = rev.revision + 1;
    assert.equal(verifyAwardSignature(rev, dir, rootPk, at)?.ok, false);
  });

  it("AW-8 (MUST, fail closed): a present-but-unsigned award is an authenticity failure, not a silent accept", () => {
    const unsigned = base();
    unsigned.award = { ...unsigned.award!, sig: undefined };
    const check = verifyAwardSignature(unsigned, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /not signed/);
    assert.equal(awardIsAuthentic(unsigned, dir, rootPk, at), false);
  });

  it("AW-9 (MUST): an award signature declaring an unsupported alg is refused", () => {
    const t = base();
    // Valid buyer signature bytes, but the sig claims a scheme the verifier does not accept.
    t.award = { ...t.award!, sig: { ...t.award!.sig!, alg: "ML-DSA-65" } as Signature };
    const check = verifyAwardSignature(t, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /unsupported alg/);
  });

  it("AW-10 (MUST, fail closed): a non-canonicalizable body returns 'not verified', never throws", () => {
    const bad = base();
    // A hostile thickness makes the quoteable body (hence traveler_hash, hence the
    // award body) uncanonicalizable; verification must return ok:false, not throw.
    bad.part = { ...bad.part, material: { spec: "6061-T6", thickness_mm: 1e308 } };
    let check: SigCheck | undefined;
    assert.doesNotThrow(() => {
      check = verifyAwardSignature(bad, dir, rootPk, at);
    });
    assert.equal(check?.ok, false);
  });

  it("AW-11 (MUST): the award domain is distinct — a signature over the same bytes under another domain does not verify as an award", () => {
    const t = base();
    // Sign the exact award body, but under the TRAVELER domain, with the buyer's key.
    const body = awardSignatureBody(t);
    const crossDomain: Signature = {
      alg: SIG_ALG,
      kid: "northline-2026",
      sig: signBody(SIG_DOMAIN.traveler, body, northline.secretKey),
    };
    assert.notEqual(SIG_DOMAIN.award, SIG_DOMAIN.traveler);
    t.award = { ...t.award!, sig: crossDomain };
    assert.equal(verifyAwardSignature(t, dir, rootPk, at)?.ok, false);
  });

  it("AW-12: a traveler with no award yields 'nothing to verify' (undefined), distinct from a failure", () => {
    const noAward = { ...base(), award: null };
    assert.equal(verifyAwardSignature(noAward, dir, rootPk, at), undefined);
    assert.equal(awardIsAuthentic(noAward, dir, rootPk, at), false);
  });

  it("AW-13 (MUST): the signature binds the awarded quote's priced content — a swapped unit price is refused", () => {
    // The awarded quote (qot_conform01) is present and unsigned — the exact gap case.
    const swapped = base();
    const q = swapped.quotes!.find((x) => x.quote_id === swapped.award!.quote_id)!;
    q.pricing.lines[0].unit = q.pricing.lines[0].unit + 1;
    const check = verifyAwardSignature(swapped, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /quote content does not match|quote_hash/);
    assert.equal(awardIsAuthentic(swapped, dir, rootPk, at), false);
  });

  it("AW-14 (MUST, hard fail): the awarded quote must be present — a stripped awarded quote is refused", () => {
    const stripped = { ...base(), quotes: [] };
    const check = verifyAwardSignature(stripped, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /not present/);
  });

  it("AW-15 (MUST): a signed award must carry a quote_hash — an award signed without one is refused", () => {
    const t = base();
    const { quote_hash: _omit, ...awardNoHash } = t.award!;
    void _omit;
    // Re-sign the award body WITHOUT a quote_hash, with the real buyer key: the buyer signature
    // verifies over that body, but the binding is missing, so the award is refused.
    t.award = { ...awardNoHash, sig: undefined };
    t.award.sig = signAward(t, "northline-2026", northline.secretKey);
    const check = verifyAwardSignature(t, dir, rootPk, at);
    assert.equal(check?.ok, false);
    assert.match(check?.reason ?? "", /quote_hash/);
  });
});
