import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { parseTraveler } from "./conformance.ts";
import {
  verifyTravelerSignatures,
  travelerIsAuthentic,
  signTraveler,
  signQuote,
  verifyQuoteSignature,
  itarAttestationBlocker,
  type SigCheck,
} from "./authenticity.ts";
import { keypairFromSeed } from "./signature.ts";
import { hexToBytes } from "./bytes.ts";
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
    // malformed root key hex fails closed (returns false), never throws (L1)
    assert.equal(travelerIsAuthentic(t, dir, "not-hex", at), false);
  });

  it("refuses an author that names no org_id even with a valid signature (H2)", () => {
    // seed 0x22.. is org_huron's key (kid huron-2026) in the vector directory.
    const kp = keypairFromSeed(hexToBytes("22".repeat(32)));
    const base = parseTraveler(vec.traveler);
    // Same key signs both; the ONLY difference is whether the body names an org.
    const unbound: Traveler = { ...structuredClone(base), buyer: { name: base.buyer.name } };
    unbound.signatures = [signTraveler(unbound, "huron-2026", kp.secretKey)];
    const bound: Traveler = {
      ...structuredClone(base),
      buyer: { name: base.buyer.name, org_id: "org_huron" },
    };
    bound.signatures = [signTraveler(bound, "huron-2026", kp.secretKey)];
    // A cryptographically valid signature is NOT enough: authorship must bind to org_id.
    assert.equal(travelerIsAuthentic(unbound, dir, rootPk, at), false);
    assert.equal(travelerIsAuthentic(bound, dir, rootPk, at), true);
  });

  it("gates ITAR on the directory-attested capability, not seller self-declaration", () => {
    const base = parseTraveler(vec.traveler);
    const itarT: Traveler = { ...base, itar: true };
    // org_huron is ITAR-attested; org_summitfab is not
    assert.equal(itarAttestationBlocker(itarT, quoteFor("org_huron"), dir, rootPk, at), null);
    assert.ok(itarAttestationBlocker(itarT, quoteFor("org_summitfab"), dir, rootPk, at));
    // a non-ITAR traveler imposes no gate
    assert.equal(
      itarAttestationBlocker({ ...base, itar: false }, quoteFor("org_summitfab"), dir, rootPk, at),
      null,
    );
  });

  it("refuses ITAR attestation from a directory that does not verify against the root (M1)", () => {
    const itarT: Traveler = { ...parseTraveler(vec.traveler), itar: true };
    // Flip summitfab's ITAR capability without re-signing: the directory no longer
    // verifies against the root, so the gate must refuse rather than trust it.
    const forged: Directory = structuredClone(dir);
    forged.entries.find((e) => e.org_id === "org_summitfab")!.capabilities = { itar: true };
    assert.ok(itarAttestationBlocker(itarT, quoteFor("org_summitfab"), forged, rootPk, at));
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

  it("fails closed (never throws) on a non-canonicalizable body (D3)", () => {
    // A quote's assumptions/capacity are opaque blobs and may hold arbitrary
    // numbers; a hostile value (> 2^53) makes the signature body uncanonicalizable.
    // Verification must return ok:false, not throw an uncaught exception.
    const quote = quoteFor("org_huron");
    quote.assumptions = { hostile: 1e308 };
    quote.sig = { alg: "ML-DSA-87", kid: "huron-2026", sig: "ab" };
    let check: SigCheck | undefined;
    assert.doesNotThrow(() => {
      check = verifyQuoteSignature(quote, dir, rootPk, at);
    });
    assert.equal(check?.ok, false);

    // Same for a traveler body built with an out-of-range number (bypassing parse).
    const badTraveler = {
      ...parseTraveler(vec.traveler),
      part: { ...parseTraveler(vec.traveler).part, material: { spec: "6061-T6", thickness_mm: 1e308 } },
      signatures: [{ alg: "ML-DSA-87", kid: "northline-2026", sig: "ab" }],
    } as Traveler;
    let checks: SigCheck[] | undefined;
    assert.doesNotThrow(() => {
      checks = verifyTravelerSignatures(badTraveler, dir, rootPk, at);
    });
    assert.equal(checks![0]!.ok, false);
  });
});

describe("directory validity windows (entry level)", () => {
  const ev = JSON.parse(
    readFileSync(
      new URL("../../../conformance/signatures/directory-expired-entry.json", import.meta.url),
      "utf8",
    ),
  ) as {
    root_public_key_hex: string;
    valid_at_ms: number;
    expired_at_ms: number;
    directory: Directory;
    traveler: Traveler;
  };

  it("accepts authorship while the signer entry is in window, refuses it once expired (H1)", () => {
    const t = parseTraveler(ev.traveler);
    // The directory itself is valid at both instants; only the entry's window moves.
    assert.equal(
      travelerIsAuthentic(t, ev.directory, ev.root_public_key_hex, new Date(ev.valid_at_ms)),
      true,
    );
    assert.equal(
      travelerIsAuthentic(t, ev.directory, ev.root_public_key_hex, new Date(ev.expired_at_ms)),
      false,
    );
  });
});

describe("seller quote authorship (signed-quote vector)", () => {
  const qv = JSON.parse(
    readFileSync(
      new URL("../../../conformance/signatures/signed-quote.json", import.meta.url),
      "utf8",
    ),
  ) as { root_public_key_hex: string; at_ms: number; directory: Directory; quote: Quote };
  const when = new Date(qv.at_ms);

  it("verifies the seller quote signature against the directory", () => {
    const check = verifyQuoteSignature(qv.quote, qv.directory, qv.root_public_key_hex, when);
    assert.equal(check?.ok, true);
    assert.equal(check?.org_id, "org_huron");
    // tampering the quote body breaks the signature
    const tampered: Quote = { ...structuredClone(qv.quote), lead_time_days: 999 };
    assert.equal(
      verifyQuoteSignature(tampered, qv.directory, qv.root_public_key_hex, when)?.ok,
      false,
    );
  });

  it("gates ITAR on directory attestation of the seller org", () => {
    const itarT: Traveler = { ...parseTraveler(vec.traveler), itar: true };
    // org_huron IS attested -> allowed
    assert.equal(
      itarAttestationBlocker(itarT, qv.quote, qv.directory, qv.root_public_key_hex, when),
      null,
    );
    // same quote re-addressed to a non-attested org -> blocked
    const summit: Quote = {
      ...structuredClone(qv.quote),
      seller: { ...qv.quote.seller, org_id: "org_summitfab" },
    };
    assert.ok(itarAttestationBlocker(itarT, summit, qv.directory, qv.root_public_key_hex, when));
  });
});
