/** Worked example: post-quantum AUTHORSHIP signatures (ML-DSA-87).
 *
 *  Shows how a traveler's author is proven: the buyer signs the quoteable body,
 *  a verifier checks the signature against a signed key directory, and both a
 *  tampered body and a signer whose org does not match the author are refused.
 *  Signing lives in the library / CLI / server; the browser desk only *verifies*
 *  (it holds no signing keys — see SECURITY.md).
 *
 *  Run: npm run example:signatures
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { keypairFromSeed } from "../src/lib/traveler/signature.ts";
import { signTraveler, verifyTravelerSignatures } from "../src/lib/traveler/authenticity.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { parseTraveler } from "../src/lib/traveler/conformance.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";
import type { Traveler } from "../src/lib/traveler/types.ts";

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);
const AT = new Date("2027-01-01T00:00:00.000Z");

const base = parseTraveler(JSON.parse(readFileSync(new URL("./bracket.traveler.json", import.meta.url), "utf8")));
const traveler: Traveler = { ...base, buyer: { ...base.buyer, org_id: "org_northline" } };

console.log("=== SJE authorship signatures (ML-DSA-87) ===");

/* 1. A trust root signs a directory binding org_northline to a signing key. */
step(1, "Publish a signed directory binding org_northline to a signing key");
const root = keypairFromSeed(new Uint8Array(32).fill(1));
const rootPublicKeyHex = bytesToHex(root.publicKey);
const buyerKey = keypairFromSeed(new Uint8Array(32).fill(2));
const dirBody: Directory = {
  spec: DIRECTORY_SPEC,
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2030-01-01T00:00:00.000Z",
  root_kid: "root-2026",
  entries: [
    {
      org_id: "org_northline",
      kid: "northline-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(buyerKey.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
    },
  ],
};
const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };
note(`root ${rootPublicKeyHex.slice(0, 20)}… · org_northline → kid northline-2026`);

/* 2. The buyer signs the quoteable body; the verifier accepts it. */
step(2, "Buyer signs the traveler; the verifier accepts it against the directory");
const signed: Traveler = { ...traveler, signatures: [signTraveler(traveler, "northline-2026", buyerKey.secretKey)] };
const good = verifyTravelerSignatures(signed, directory, rootPublicKeyHex, AT);
note(`verified=${good.every((c) => c.ok)} · author org=${good[0]?.org_id}`);
assert.ok(good.every((c) => c.ok));

/* 3. A one-field tamper breaks the signature. */
step(3, "A tampered body no longer verifies");
const tampered: Traveler = { ...signed, part: { ...signed.part, qty: { ...signed.part.qty, target: 999 } } };
const t = verifyTravelerSignatures(tampered, directory, rootPublicKeyHex, AT);
note(`verified=${t.some((c) => c.ok)} · reason=${t[0]?.reason}`);
assert.ok(!t.some((c) => c.ok));

/* 4. A signature whose kid's org != the body's author org is refused. */
step(4, "A signer whose org does not match the author org is refused");
const wrongOrg: Traveler = { ...signed, buyer: { ...signed.buyer, org_id: "org_summitfab" } };
const w = verifyTravelerSignatures(wrongOrg, directory, rootPublicKeyHex, AT);
note(`verified=${w.some((c) => c.ok)} · reason=${w[0]?.reason}`);
assert.ok(!w.some((c) => c.ok));

console.log("\n=== DONE — authorship proven; tamper and org-mismatch refused. ===");
