/** Worked example: a post-quantum ENCRYPTED exchange between two desks.
 *
 *  Runs end to end with no server and no network. It mints two identities, publishes
 *  a signed directory and the seller's one-time prekey bundle, seals a traveler into
 *  a forward-secret `.sje` envelope, opens it, and then demonstrates the attacks the
 *  transport refuses. Everything uses the public library API
 *  (src/lib/traveler/{keystore,transport,directory,prekeys,signature}) — the same
 *  code the MCP server and the browser desk call.
 *
 *  Run: npm run example:exchange
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { keypairFromSeed } from "../src/lib/traveler/signature.ts";
import { createIdentity, unlock } from "../src/lib/traveler/keystore.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import { sealTraveler, openTraveler } from "../src/lib/traveler/transport.ts";
import type { FsEnvelope } from "../src/lib/traveler/envelope.ts";
import { parseTraveler } from "../src/lib/traveler/conformance.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);
const flip = (hex: string) => (hex[0] === "a" ? "b" : "a") + hex.slice(1);

// Demo passphrases (>= 12 chars). Real desks use a human-entered secret.
const BUYER_PASS = "buyer desk passphrase";
const SELLER_PASS = "seller desk passphrase";
const WINDOW = { issued_at: "2026-01-01T00:00:00.000Z", valid_until: "2030-01-01T00:00:00.000Z" };

const traveler = parseTraveler(
  JSON.parse(readFileSync(new URL("./bracket.traveler.json", import.meta.url), "utf8")),
);

console.log("=== SJE encrypted exchange (post-quantum .sje) ===");

/* 1. Trust root + two desk identities (ML-KEM keys in passphrase-encrypted keystores). */
step(1, "Mint a trust root and two desk identities (encrypted keystores)");
const root = keypairFromSeed(new Uint8Array(32).fill(1));
const rootPublicKeyHex = bytesToHex(root.publicKey);
const buyer = await createIdentity({ passphrase: BUYER_PASS, orgId: "org_northline" });
const seller = await createIdentity({ passphrase: SELLER_PASS, orgId: "org_summitfab" });
note(`trust root ${rootPublicKeyHex.slice(0, 20)}… (verify this out of band)`);
note(`buyer kid ${buyer.directoryEntry.kid} · seller kid ${seller.directoryEntry.kid}`);

/* 2. Publish a signed directory + the seller's signed one-time prekey bundle. */
step(2, "Publish a signed directory and the seller's one-time prekey bundle");
const buyerSigner = keypairFromSeed(new Uint8Array(32).fill(2));
const sellerSigner = keypairFromSeed(new Uint8Array(32).fill(3));
const dirBody: Directory = {
  spec: DIRECTORY_SPEC,
  ...WINDOW,
  root_kid: "root-2026",
  entries: [
    {
      org_id: "org_northline",
      kid: "northline-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(buyerSigner.publicKey),
      valid_from: WINDOW.issued_at,
      valid_until: WINDOW.valid_until,
      status: "active",
      enc_alg: "ML-KEM-1024",
      enc_public_key: buyer.directoryEntry.enc_public_key,
    },
    {
      org_id: "org_summitfab",
      kid: "summit-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(sellerSigner.publicKey),
      valid_from: WINDOW.issued_at,
      valid_until: WINDOW.valid_until,
      status: "active",
      enc_alg: "ML-KEM-1024",
      enc_public_key: seller.directoryEntry.enc_public_key,
    },
  ],
};
const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };

// The seller mints one-time prekeys and signs a bundle with its directory key. The
// unlocked keystore holds the prekey secrets; it is what opens received envelopes.
const sellerDesk = await unlock(seller.keystore, SELLER_PASS);
const { prekeys } = sellerDesk.addPrekeys(2);
const bundleBody: PrekeyBundle = {
  spec: PREKEY_BUNDLE_SPEC,
  org_id: "org_summitfab",
  kid: "summit-2026",
  enc_alg: "ML-KEM-1024",
  ...WINDOW,
  prekeys,
};
bundleBody.sig = signPrekeyBundle(bundleBody, sellerSigner.secretKey);
note(`directory: ${directory.entries.length} orgs · seller published ${prekeys.length} one-time prekeys`);

/* 3. Buyer seals the traveler to the seller — forward-secret because a bundle exists. */
step(3, "Buyer seals the traveler to the seller (forward-secret)");
const { envelope, forwardSecret } = await sealTraveler(traveler, {
  directory,
  rootPublicKeyHex,
  recipientOrg: "org_summitfab",
  prekeyBundle: bundleBody,
  prekeyId: prekeys[0]!.prekey_id,
});
assert.equal(forwardSecret, true);
note(`${envelope.spec} · forward_secret=${forwardSecret} — the only artifact that leaves the buyer`);

/* 4. The .sje is ciphertext — nothing about the job leaks in the clear. */
step(4, "The sealed .sje is ciphertext — no plaintext fields, not a zip");
const wire = JSON.stringify(envelope);
assert.ok(!wire.includes(traveler.traveler_id), "traveler_id leaked");
assert.ok(!wire.includes(traveler.buyer.name), "buyer name leaked");
assert.ok(!wire.includes(traveler.part.part_number), "part number leaked");
assert.ok(!Buffer.from(envelope.payload, "hex").includes(Buffer.from("PK\x03\x04")), "ZIP header in payload");
note("no traveler_id / buyer / part_number in the clear; no ZIP header in the payload");

/* 5. Seller opens the envelope with its unlocked keystore (consuming the prekey). */
step(5, "Seller opens the envelope — decrypts, then runs the full defensive import");
const opened = await openTraveler(envelope, sellerDesk);
assert.deepEqual(opened, traveler);
note(`decrypted ${opened.traveler_id} — identical to what the buyer sealed`);

/* 6. The attacks the transport refuses. */
step(6, "Attacks the transport refuses");

// (a) A one-byte flip in the ciphertext.
await assert.rejects(() => openTraveler({ ...envelope, payload: flip(envelope.payload) }, sellerDesk));
note("a one-byte flip in the ciphertext is refused (AEAD)");

// (b) The wrong desk's keystore cannot open an envelope addressed to the seller.
const buyerDesk = await unlock(buyer.keystore, BUYER_PASS);
await assert.rejects(() => openTraveler(envelope, buyerDesk), /no recipient entry/);
note("the wrong desk's keystore cannot open it");

// (c) A forged envelope naming a real, still-unused prekey_id must NOT burn the prekey.
const otherId = prekeys[1]!.prekey_id;
const sealToOther = () =>
  sealTraveler(traveler, { directory, rootPublicKeyHex, recipientOrg: "org_summitfab", prekeyBundle: bundleBody, prekeyId: otherId });
const legit = (await sealToOther()).envelope as FsEnvelope;
await assert.rejects(() => openTraveler({ ...legit, payload: flip(legit.payload) }, sellerDesk));
assert.deepEqual(await openTraveler((await sealToOther()).envelope, sellerDesk), traveler);
note("a forged envelope naming a real prekey_id fails WITHOUT burning the prekey");

// (d) No silent downgrade: requiring forward secrecy with no usable prekey is refused.
await assert.rejects(
  () => sealTraveler(traveler, { directory, rootPublicKeyHex, recipientOrg: "org_summitfab", requireForwardSecret: true }),
  /forward secrecy required/,
);
note("requireForwardSecret refuses to downgrade when no prekey is available");

console.log("\n=== DONE — one encrypted exchange; ciphertext on the wire; every attack refused. ===");
