/** Regenerates the conformance vectors from the TypeScript reference
 *  implementation. The Rust implementation then verifies the same files
 *  independently — agreement across two codebases with no shared code is
 *  the proof the vectors encode.
 *
 *  Run: node --experimental-strip-types conformance/generate.ts
 */
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { canonicalJson } from "../src/lib/traveler/canonical.ts";
import { travelerHash, hashQuoteable, quoteableBody } from "../src/lib/traveler/hash.ts";
import { parseTraveler, levelOf } from "../src/lib/traveler/conformance.ts";
import { keypairFromSeed, signBody, SIG_DOMAIN } from "../src/lib/traveler/signature.ts";
import { bytesToHex, utf8ToBytes } from "../src/lib/traveler/bytes.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { signTraveler, signQuote } from "../src/lib/traveler/authenticity.ts";
import { PREKEY_BUNDLE_SPEC, signPrekeyBundle, type PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import {
  kemKeypairFromSeed,
  sealEnvelopeDeterministic,
  recipientByOrg,
  sealFsEnvelopeDeterministic,
  fsRecipientFromBundle,
} from "../src/lib/traveler/envelope.ts";
import { sha384 } from "@noble/hashes/sha2.js";
import type { Traveler, Quote } from "../src/lib/traveler/types.ts";

const here = new URL(".", import.meta.url).pathname;

/* ---------- canonicalization vectors ---------- */

const validValues: Array<{ name: string; value: unknown }> = [
  { name: "sorted-keys", value: { b: 1, a: 2 } },
  { name: "nested-sort", value: { z: { d: 4, c: [3, { b: 2, a: 1 }] }, a: null } },
  { name: "integer", value: { t: 10 } },
  { name: "decimal", value: { t: 9.53 } },
  { name: "negative-zero", value: { t: -0 } },
  { name: "min-fraction", value: { t: 0.00001 } },
  { name: "max-safe-integer", value: { t: 9007199254740991 } },
  { name: "negative-decimal", value: { t: -12.75 } },
  { name: "string-escapes", value: { s: 'a"b\\c\nd\te' } },
  { name: "unicode-raw-utf8", value: { s: "café ± µm Ø12" } },
  { name: "empty-structures", value: { obj: {}, arr: [], s: "" } },
  { name: "booleans-null", value: { t: true, f: false, n: null } },
  { name: "key-order-digits", value: { "10": 1, "2": 2, A: 3, a: 4 } },
];

const invalidValues: Array<{ name: string; value: unknown; reason: string }> = [
  { name: "exp-large", value: { t: 1e21 }, reason: "renders exponential (1e+21 vs 1e21)" },
  { name: "exp-small", value: { t: 1e-7 }, reason: "renders exponential" },
  { name: "below-min-fraction", value: { t: 0.000001 }, reason: "ryu renders 1e-6, JS stays fixed" },
  { name: "negative-exp-large", value: { t: -1e21 }, reason: "renders exponential" },
];

const canonical = {
  spec: "sje/0.1.0",
  note:
    "Valid: implementations MUST produce exactly `canonical` and `sha384` for `value`. " +
    "Invalid: implementations MUST refuse to canonicalize `value`. " +
    "Integers above 2^53-1 are also refused but cannot be expressed in a shared JSON " +
    "vector file (JSON.parse in JavaScript loses their precision), so that rule is " +
    "covered by language-local unit tests on both sides.",
  valid: validValues.map(({ name, value }) => {
    const c = canonicalJson(value);
    return { name, value, canonical: c, sha384: `sha384:${bytesToHex(sha384(utf8ToBytes(c)))}` };
  }),
  invalid: invalidValues,
};

writeFileSync(`${here}/canonical.json`, JSON.stringify(canonical, null, 2) + "\n");

/* ---------- traveler vectors ---------- */

const l0: Traveler = JSON.parse(
  readFileSync(`${here}/../examples/bracket.traveler.json`, "utf8"),
) as Traveler;
l0.traveler_id = "tvl_conform0l0";

const l0Hash = travelerHash(l0);

const quote: Quote = {
  quote_id: "qot_conform01",
  seller: {
    org_id: "org_summitfab",
    name: "Summit Fabrication",
    city: "Sparks",
    region: "NV",
    certs: ["ISO 9001"],
  },
  traveler_hash_quoted: l0Hash,
  created_at: "2026-09-16T12:00:00.000Z",
  valid_until: "2039-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: {
    currency: "USD",
    nre: 35000,
    lines: [
      { qty: 100, unit: 1850 },
      { qty: 250, unit: 1420 },
      { qty: 500, unit: 1175 },
    ],
  },
};

const l1: Traveler = { ...structuredClone(l0), traveler_id: "tvl_conform0l1", quotes: [] };
const l1Hash = travelerHash(l1);
l1.quotes = [{ ...structuredClone(quote), traveler_hash_quoted: l1Hash }];

const l2: Traveler = { ...structuredClone(l1), traveler_id: "tvl_conform0l2" };
const l2Hash = travelerHash(l2);
l2.quotes = [{ ...structuredClone(quote), traveler_hash_quoted: l2Hash }];
l2.award = {
  quote_id: "qot_conform01",
  awarded_at: "2026-09-17T09:00:00.000Z",
  qty: 250,
  terms: {
    governing_law: "US-DE",
    warranty: "12 months, parts and labor",
    payment_terms: "Net 30",
  },
};
l2.ops = [
  { seq: 1, code: "laser" },
  { seq: 2, code: "cnc-mill" },
  { seq: 3, code: "deburr" },
];
l2.ship_to = {
  name: "Northline Equipment — Dock 4",
  line1: "1800 Industrial Way",
  city: "Reno",
  region: "NV",
  postal: "89502",
  country: "US",
};

// Empty arrays / strings MUST be dropped from the quoteable body identically
// on both implementations. This vector pins that: a naive Rust serializer that
// keeps `Some(vec![])` as `[]` produces a different hash and fails here.
const emptyArrays: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_conformempt",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment", certs: [] },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50, breaks: [] },
    processes: [],
  },
  itar: false,
};

const expected: Record<string, { traveler_hash: string; level: string }> = {};
for (const [file, p] of [
  ["l0-bracket.json", l0],
  ["l0-empty-arrays.json", emptyArrays],
  ["l1-quoted.json", l1],
  ["l2-awarded.json", l2],
] as const) {
  const parsed = parseTraveler(JSON.parse(JSON.stringify(p)));
  expected[file] = { traveler_hash: travelerHash(parsed), level: levelOf(parsed).code };
  writeFileSync(`${here}/travelers/${file}`, JSON.stringify(p, null, 2) + "\n");
}
writeFileSync(`${here}/travelers/expected.json`, JSON.stringify(expected, null, 2) + "\n");

// sanity: golden vector must still hold
const golden = JSON.parse(
  readFileSync(`${here}/../crates/secure-job-envelope/tests/golden.json`, "utf8"),
);
console.log("golden:", hashQuoteable(golden));
console.log("levels:", Object.fromEntries(Object.entries(expected).map(([k, v]) => [k, v.level])));
console.log("vectors written");

// keep quoteableBody import used (documents that hashes cover the closed body)
void quoteableBody;

/* ---------- signature vector (ML-DSA-87 / FIPS 204) ---------- */
// A deterministic keypair from a fixed 32-byte seed. Both implementations MUST
// derive the same public key, produce the same signature over the same
// domain-separated canonical body, and verify it — proving cross-language
// agreement on post-quantum authorship, not just on the content hash.
const sigSeed = new Uint8Array(32);
for (let i = 0; i < 32; i++) sigSeed[i] = i;
const sigKp = keypairFromSeed(sigSeed);
const sigBody = canonicalJson(golden);
const signatureVector = {
  spec: "sje/0.1.0",
  note:
    "ML-DSA-87 (FIPS 204) authorship signature over domain-separated canonical bytes. " +
    "Implementations MUST derive public_key_hex from seed_hex, produce signature_hex " +
    "deterministically when signing canonical_body under domain, and verify it. The " +
    "signed message is domain + 0x00 + canonical_body.",
  alg: "ML-DSA-87",
  domain: SIG_DOMAIN.traveler,
  seed_hex: bytesToHex(sigSeed),
  public_key_hex: bytesToHex(sigKp.publicKey),
  canonical_body: sigBody,
  signature_hex: signBody(SIG_DOMAIN.traveler, sigBody, sigKp.secretKey),
};
mkdirSync(`${here}/signatures`, { recursive: true });
writeFileSync(
  `${here}/signatures/traveler-sig.json`,
  JSON.stringify(signatureVector, null, 2) + "\n",
);
console.log("signature vector written");

/* ---------- signed key directory vector ---------- */
// A trust root signs a directory of org -> key entries (with ITAR capability
// attested per org). Both implementations verify the directory signature over
// the canonical directory body, so org identity and capability are cross-checked.
const fill = (b: number) => new Uint8Array(32).fill(b);
const rootKp = keypairFromSeed(fill(0x11));
const huronKp = keypairFromSeed(fill(0x22));
const summitKp = keypairFromSeed(fill(0x33));
const northlineKp = keypairFromSeed(fill(0x44));
// Per-org ML-KEM-1024 encryption keys, attested alongside the signing keys so a
// sealer can resolve a recipient's key through the trust root (M3).
const huronKemSeed = new Uint8Array(64).fill(0x51);
const summitKemSeed = new Uint8Array(64).fill(0x52);
const northlineKemSeed = new Uint8Array(64).fill(0x53);
const huronKem = kemKeypairFromSeed(huronKemSeed);
const summitKem = kemKeypairFromSeed(summitKemSeed);
const northlineKem = kemKeypairFromSeed(northlineKemSeed);
const directory: Directory = {
  spec: DIRECTORY_SPEC,
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2030-01-01T00:00:00.000Z",
  root_kid: "root-2026",
  entries: [
    {
      org_id: "org_huron",
      kid: "huron-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(huronKp.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: { itar: true },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(huronKem.publicKey),
    },
    {
      org_id: "org_summitfab",
      kid: "summit-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(summitKp.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: { itar: false },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(summitKem.publicKey),
    },
    {
      org_id: "org_northline",
      kid: "northline-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(northlineKp.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: { itar: false },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(northlineKem.publicKey),
    },
  ],
};
const directoryVector = {
  note:
    "Signed key directory. Verify the directory signature (directory.sig) with " +
    "root_public_key_hex over the canonical directory body (the directory with its " +
    "own sig removed), then trust each entry's org_id -> public_key and capabilities.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  directory: { ...directory, sig: signDirectory(directory, rootKp.secretKey) },
};
writeFileSync(`${here}/signatures/directory.json`, JSON.stringify(directoryVector, null, 2) + "\n");
console.log("directory vector written");

/* ---------- signed traveler vector (end-to-end authorship) ---------- */
// A real traveler carrying a buyer authorship signature, plus the directory and
// root key needed to verify it. Both implementations run the full chain:
// directory verifies -> signature kid resolves to buyer.org_id -> ML-DSA verify.
const signedTraveler: Traveler = structuredClone(l0);
signedTraveler.traveler_id = "tvl_signed00001";
signedTraveler.buyer = { ...signedTraveler.buyer, org_id: "org_northline" };
signedTraveler.signatures = [signTraveler(signedTraveler, "northline-2026", northlineKp.secretKey)];
const signedTravelerVector = {
  note:
    "End-to-end authorship. Verify the directory against root_public_key_hex, resolve the " +
    "traveler signature's kid to a directory entry whose org_id equals buyer.org_id, then " +
    "verify the ML-DSA-87 signature over the canonical quoteable body. A tampered body, a " +
    "wrong signer org, or a broken directory all fail.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  directory: directoryVector.directory,
  traveler: signedTraveler,
};
writeFileSync(
  `${here}/signatures/signed-traveler.json`,
  JSON.stringify(signedTravelerVector, null, 2) + "\n",
);
console.log("signed traveler vector written");

/* ---------- expired-entry directory vector (validity-window enforcement) ---------- */
// The directory itself is valid to 2030, but the org_northline signer entry
// expires mid-window (2026-07-01). Both implementations MUST verify authorship at
// valid_at_ms (entry still valid) and MUST refuse it at expired_at_ms (entry
// expired though the directory is still valid) — proving entry-level window
// enforcement distinct from the directory-level window (audit H1).
const expiringDir: Directory = structuredClone(directory);
const expiringNorthline = expiringDir.entries.find((e) => e.org_id === "org_northline")!;
expiringNorthline.valid_until = "2026-07-01T00:00:00.000Z";
const expiredEntryVector = {
  note:
    "Entry-level validity window. The directory runs to 2030 but the org_northline " +
    "entry expires 2026-07-01. Implementations MUST verify authorship at valid_at_ms " +
    "(entry in window) and MUST refuse it at expired_at_ms (entry expired, directory " +
    "still valid).",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  valid_at_ms: Date.parse("2026-03-01T00:00:00.000Z"),
  expired_at_ms: Date.parse("2027-01-01T00:00:00.000Z"),
  directory: { ...expiringDir, sig: signDirectory(expiringDir, rootKp.secretKey) },
  traveler: signedTraveler,
};
writeFileSync(
  `${here}/signatures/directory-expired-entry.json`,
  JSON.stringify(expiredEntryVector, null, 2) + "\n",
);
console.log("expired-entry directory vector written");

/* ---------- encrypted envelope vector (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM) ---------- */
// Deterministic seal (fixed CEK / nonces / KEM coins). Both implementations must
// re-seal to the same ciphertext bytes and both must decrypt it to the plaintext.
const envRecipient = recipientByOrg(
  directoryVector.directory,
  "org_northline",
  new Date("2027-01-01T00:00:00.000Z"),
)!;
const det = {
  cek: new Uint8Array(32).fill(0x2a),
  payload_nonce: new Uint8Array(12).fill(0x01),
  coins: [new Uint8Array(32).fill(0x09)],
  wrap_nonces: [new Uint8Array(12).fill(0x02)],
};
const envPlaintext = canonicalJson(golden);
const envelope = sealEnvelopeDeterministic(
  new TextEncoder().encode(envPlaintext),
  [envRecipient],
  det,
);
const envelopeVector = {
  note:
    "Encrypted envelope, deterministic seal to a directory-attested recipient. The recipient's " +
    "ML-KEM key is resolved from the signed directory (org_northline) and the recipient kid is " +
    "derived from that key (enc_kid). Implementations re-seal plaintext_utf8 with the fixed " +
    "determinism values and MUST reproduce envelope byte-for-byte, and MUST decrypt it back to " +
    "plaintext_utf8 with the recipient seed. The payload AAD binds {spec, enc_alg, recipients}.",
  recipient: {
    kid: envRecipient.kid,
    org_id: "org_northline",
    seed_hex: bytesToHex(northlineKemSeed),
    public_key_hex: envRecipient.public_key,
  },
  determinism: {
    cek_hex: bytesToHex(det.cek),
    payload_nonce_hex: bytesToHex(det.payload_nonce),
    coins_hex: bytesToHex(det.coins[0]!),
    wrap_nonce_hex: bytesToHex(det.wrap_nonces[0]!),
  },
  plaintext_utf8: envPlaintext,
  envelope,
};
writeFileSync(`${here}/signatures/envelope.json`, JSON.stringify(envelopeVector, null, 2) + "\n");
console.log("envelope vector written");

/* ---------- signed quote vector (seller authorship) ---------- */
// A seller quote carrying an ML-DSA-87 signature, with the directory and root key
// needed to verify it. Both implementations verify the directory, resolve the
// quote signature's kid to a directory entry whose org_id equals seller.org_id,
// and verify the signature over the canonical quote body (the quote with its own
// sig removed). org_huron is ITAR-attested, so the same vector exercises the
// directory-attested ITAR gate.
const signedQuote: Quote = {
  quote_id: "qot_signed00001",
  seller: {
    org_id: "org_huron",
    name: "Huron Precision",
    city: "Ann Arbor",
    region: "MI",
    certs: ["AS9100"],
    itar: true,
  },
  traveler_hash_quoted: l0Hash,
  created_at: "2026-02-01T00:00:00.000Z",
  valid_until: "2027-02-01T00:00:00.000Z",
  lead_time_days: 18,
  pricing: { currency: "USD", nre: 25000, lines: [{ qty: 100, unit: 1600 }] },
};
signedQuote.sig = signQuote(signedQuote, "huron-2026", huronKp.secretKey);
const signedQuoteVector = {
  note:
    "Seller quote authorship. Verify the directory against root_public_key_hex, resolve the " +
    "quote sig's kid to a directory entry whose org_id equals seller.org_id, then verify the " +
    "ML-DSA-87 signature over the canonical quote body (the quote with its own sig removed). " +
    "Evaluate at at_ms (inside the directory and entry windows). org_huron is ITAR-attested.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  at_ms: Date.parse("2026-06-01T00:00:00.000Z"),
  directory: directoryVector.directory,
  quote: signedQuote,
};
writeFileSync(
  `${here}/signatures/signed-quote.json`,
  JSON.stringify(signedQuoteVector, null, 2) + "\n",
);
console.log("signed quote vector written");

/* ---------- signed one-time prekey bundle vector (forward secrecy) ---------- */
// A recipient org (org_northline) publishes one-time ML-KEM-1024 prekeys, the
// whole bundle signed by its ML-DSA identity key (kid northline-2026). Both
// implementations verify the bundle against the directory: kid -> org_northline,
// the bundle's own window covers at_ms, and the ML-DSA signature over the
// canonical body checks out. These prekeys are reused by the FS envelope vector.
const prekeySeeds = [new Uint8Array(64).fill(0x61), new Uint8Array(64).fill(0x62)];
const prekeyKps = prekeySeeds.map((s) => kemKeypairFromSeed(s));
const prekeyBundle: PrekeyBundle = {
  spec: PREKEY_BUNDLE_SPEC,
  org_id: "org_northline",
  kid: "northline-2026",
  enc_alg: "ML-KEM-1024",
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2027-01-01T00:00:00.000Z",
  prekeys: prekeyKps.map((kp, i) => ({
    prekey_id: `northline-ot-${i + 1}`,
    public_key: bytesToHex(kp.publicKey),
  })),
};
prekeyBundle.sig = signPrekeyBundle(prekeyBundle, northlineKp.secretKey);
const prekeyBundleVector = {
  note:
    "Signed one-time prekey bundle. Verify the directory against root_public_key_hex, resolve " +
    "the bundle's kid to a directory entry whose org_id equals the bundle's org_id, check the " +
    "bundle's own window covers at_ms, then verify the ML-DSA signature over the canonical bundle " +
    "body (bundle minus its own sig). prekey_seeds regenerate each one-time ML-KEM keypair.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  at_ms: Date.parse("2026-06-01T00:00:00.000Z"),
  directory: directoryVector.directory,
  bundle: prekeyBundle,
  prekey_seeds: prekeyKps.map((_, i) => ({
    prekey_id: `northline-ot-${i + 1}`,
    seed_hex: bytesToHex(prekeySeeds[i]!),
  })),
};
writeFileSync(
  `${here}/signatures/prekey-bundle.json`,
  JSON.stringify(prekeyBundleVector, null, 2) + "\n",
);
console.log("prekey bundle vector written");

/* ---------- forward-secret envelope vector (two-KEM: one-time prekey + static) ---------- */
// Seals to org_northline using one verified one-time prekey (northline-ot-1) plus
// northline's static identity ML-KEM key from the directory. The KEK binds both
// shared secrets (one-time || static). Both implementations re-seal byte-for-byte
// and open with BOTH the static and one-time secret keys.
const fsRecipient = fsRecipientFromBundle(
  directoryVector.directory,
  prekeyBundle,
  "org_northline",
  "northline-ot-1",
  bytesToHex(rootKp.publicKey),
  new Date("2026-06-01T00:00:00.000Z"),
)!;
const fsDet = {
  cek: new Uint8Array(32).fill(0x3a),
  payload_nonce: new Uint8Array(12).fill(0x03),
  coins_onetime: [new Uint8Array(32).fill(0x0a)],
  coins_static: [new Uint8Array(32).fill(0x0b)],
  wrap_nonces: [new Uint8Array(12).fill(0x04)],
};
const fsPlaintext = canonicalJson(golden);
const fsEnvelope = sealFsEnvelopeDeterministic(
  new TextEncoder().encode(fsPlaintext),
  [fsRecipient],
  fsDet,
);
const fsEnvelopeVector = {
  note:
    "Forward-secret envelope (sje-envelope/0.2.0). Encapsulates to a one-time prekey AND the " +
    "static identity key; the KEK binds both shared secrets (one-time || static). Implementations " +
    "re-seal plaintext_utf8 with the fixed determinism values and MUST reproduce envelope " +
    "byte-for-byte, and MUST decrypt it with BOTH the static and one-time seeds. Deleting the " +
    "one-time secret after opening is what gives forward secrecy.",
  recipient: {
    kid: fsRecipient.kid,
    org_id: "org_northline",
    prekey_id: "northline-ot-1",
    static_seed_hex: bytesToHex(northlineKemSeed),
    onetime_seed_hex: bytesToHex(prekeySeeds[0]!),
    static_public_key_hex: fsRecipient.static_public_key,
    onetime_public_key_hex: fsRecipient.onetime_public_key,
  },
  determinism: {
    cek_hex: bytesToHex(fsDet.cek),
    payload_nonce_hex: bytesToHex(fsDet.payload_nonce),
    coins_onetime_hex: bytesToHex(fsDet.coins_onetime[0]!),
    coins_static_hex: bytesToHex(fsDet.coins_static[0]!),
    wrap_nonce_hex: bytesToHex(fsDet.wrap_nonces[0]!),
  },
  plaintext_utf8: fsPlaintext,
  envelope: fsEnvelope,
};
writeFileSync(
  `${here}/signatures/fs-envelope.json`,
  JSON.stringify(fsEnvelopeVector, null, 2) + "\n",
);
console.log("fs envelope vector written");
