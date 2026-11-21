/** Worked example: post-quantum AUTHORSHIP + AWARD signatures (ML-DSA-87).
 *
 *  Shows how a traveler's author AND its award are proven: the buyer signs the
 *  quoteable body and, separately, the award (the award decision + ship-to); a
 *  verifier checks both against a signed key directory; and a tampered body, a
 *  wrong-org signer, an altered ship-to, and a losing bidder's forged award are
 *  all refused. The last two are the business-email-compromise case the envelope
 *  is meant to kill: anyone with a recipient's public key can seal to them, so an
 *  award / ship-to that is not signed by the buyer must not be trusted.
 *
 *  Signing lives in the library / CLI / server; the browser desk only *verifies*
 *  (it holds no signing keys — see SECURITY.md).
 *
 *  Run: npm run example:signatures
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { keypairFromSeed } from "../src/lib/traveler/signature.ts";
import {
  signTraveler,
  verifyTravelerSignatures,
  signAward,
  verifyAwardSignature,
} from "../src/lib/traveler/authenticity.ts";
import {
  signDirectory,
  DIRECTORY_SPEC,
  type Directory,
  type DirectoryEntry,
} from "../src/lib/traveler/directory.ts";
import { parseTraveler } from "../src/lib/traveler/conformance.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";
import type { Traveler } from "../src/lib/traveler/types.ts";

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);
const AT = new Date("2027-01-01T00:00:00.000Z");

const base = parseTraveler(
  JSON.parse(readFileSync(new URL("./bracket.traveler.json", import.meta.url), "utf8")),
);
const traveler: Traveler = { ...base, buyer: { ...base.buyer, org_id: "org_northline" } };

console.log("=== SJE authorship + award signatures (ML-DSA-87) ===");

/* 1. A trust root signs a directory binding the buyer AND a competing bidder. */
step(1, "Publish a signed directory: the buyer (org_northline) and a bidder (org_summitfab)");
const root = keypairFromSeed(new Uint8Array(32).fill(1));
const rootPublicKeyHex = bytesToHex(root.publicKey);
const buyerKey = keypairFromSeed(new Uint8Array(32).fill(2));
const bidderKey = keypairFromSeed(new Uint8Array(32).fill(3));
const entry = (org_id: string, kid: string, publicKey: Uint8Array): DirectoryEntry => ({
  org_id,
  kid,
  alg: "ML-DSA-87",
  public_key: bytesToHex(publicKey),
  valid_from: "2026-01-01T00:00:00.000Z",
  valid_until: "2030-01-01T00:00:00.000Z",
  status: "active",
});
const dirBody: Directory = {
  spec: DIRECTORY_SPEC,
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2030-01-01T00:00:00.000Z",
  root_kid: "root-2026",
  entries: [
    entry("org_northline", "northline-2026", buyerKey.publicKey),
    entry("org_summitfab", "summit-2026", bidderKey.publicKey),
  ],
};
const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };
note(`root ${rootPublicKeyHex.slice(0, 20)}… · org_northline, org_summitfab`);

/* 2. The buyer signs the quoteable body; the verifier accepts it. */
step(2, "Buyer signs the traveler; the verifier accepts it against the directory");
const signed: Traveler = {
  ...traveler,
  signatures: [signTraveler(traveler, "northline-2026", buyerKey.secretKey)],
};
const good = verifyTravelerSignatures(signed, directory, rootPublicKeyHex, AT);
note(`verified=${good.every((c) => c.ok)} · author org=${good[0]?.org_id}`);
assert.ok(good.every((c) => c.ok));

/* 3. A one-field tamper breaks the signature. */
step(3, "A tampered body no longer verifies");
const tampered: Traveler = {
  ...signed,
  part: { ...signed.part, qty: { ...signed.part.qty, target: 999 } },
};
const t = verifyTravelerSignatures(tampered, directory, rootPublicKeyHex, AT);
note(`verified=${t.some((c) => c.ok)} · reason=${t[0]?.reason}`);
assert.ok(!t.some((c) => c.ok));

/* 4. A signature whose kid's org != the body's author org is refused. */
step(4, "A signer whose org does not match the author org is refused");
const wrongOrg: Traveler = { ...signed, buyer: { ...signed.buyer, org_id: "org_summitfab" } };
const w = verifyTravelerSignatures(wrongOrg, directory, rootPublicKeyHex, AT);
note(`verified=${w.some((c) => c.ok)} · reason=${w[0]?.reason}`);
assert.ok(!w.some((c) => c.ok));

/* 5. The buyer awards and SIGNS the award (award decision + ship-to). */
step(5, "Buyer signs the award (award + ship-to); the verifier accepts it");
const awarded: Traveler = {
  ...signed,
  ship_to: {
    name: "Northline Equipment — Dock 4",
    line1: "1800 Industrial Way",
    city: "Reno",
    region: "NV",
    postal: "89502",
    country: "US",
  },
  award: {
    quote_id: "qot_summitwin01",
    awarded_at: "2026-09-17T09:00:00.000Z",
    qty: 250,
    terms: { payment_terms: "Net 30" },
  },
};
awarded.award!.sig = signAward(awarded, "northline-2026", buyerKey.secretKey);
const a = verifyAwardSignature(awarded, directory, rootPublicKeyHex, AT);
note(`award verified=${a?.ok} · signer org=${a?.org_id}`);
assert.ok(a?.ok);

/* 6. Altering the ship-to breaks the award signature. */
step(6, "A redirected ship-to breaks the award signature");
const redirected: Traveler = {
  ...awarded,
  ship_to: { ...awarded.ship_to!, line1: "999 Attacker Rd", postal: "00000" },
};
const r = verifyAwardSignature(redirected, directory, rootPublicKeyHex, AT);
note(`award verified=${r?.ok} · reason=${r?.reason}`);
assert.ok(!r?.ok);

/* 7. A losing bidder forges an award and seals it to the winner — refused. */
step(7, "A losing bidder's forged award (signed with the bidder's own key) is refused");
const forged: Traveler = structuredClone(awarded);
forged.award = { ...forged.award!, qty: 1 }; // the bidder awards itself
forged.award.sig = signAward(forged, "summit-2026", bidderKey.secretKey);
const f = verifyAwardSignature(forged, directory, rootPublicKeyHex, AT);
note(`award verified=${f?.ok} · reason=${f?.reason}`);
assert.ok(!f?.ok);

console.log(
  "\n=== DONE — authorship and the buyer's award proven; tamper, org-mismatch, " +
    "redirected ship-to, and a bidder's forged award all refused. ===",
);
