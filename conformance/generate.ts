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
import { bytesToHex, hexToBytes, utf8ToBytes } from "../src/lib/traveler/bytes.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { signTraveler, signQuote, signAward, quoteContentHash } from "../src/lib/traveler/authenticity.ts";
import { PREKEY_BUNDLE_SPEC, signPrekeyBundle, type PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import {
  kemKeypairFromSeed,
  sealEnvelopeDeterministic,
  openEnvelope,
  recipientByOrg,
  sealFsEnvelopeDeterministic,
  fsRecipientFromBundle,
  ENVELOPE_SPEC,
  ENC_ALG,
  FS_ENC_ALG,
} from "../src/lib/traveler/envelope.ts";
import { sha384 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
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
  // Long-decimal floats (regression): both implementations must parse to the
  // same f64 and render identically. Requires serde_json's float_roundtrip on
  // the Rust side; without it these hash differently across implementations.
  { name: "long-decimal", value: { t: 223.23501793805622 } },
  { name: "long-decimal-negative", value: { t: -946696.1927003545 } },
  { name: "long-decimal-large", value: { t: 4435404841756971.5 } },
  // Astral-plane object keys must sort by code point identically on both sides
  // (JS default UTF-16 order would put U+1F600 before U+FFFF; both must agree).
  { name: "astral-key-order", value: { "\u{1F600}": 1, "￿": 2 } },
  { name: "astral-string-value", value: { s: "grüß 😀 \u{1F680}" } },
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

// Long-decimal thickness_mm (regression): the only float in the quoteable body.
// Pins cross-implementation hash parity end to end at the traveler layer.
const longFloat: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_longfloat01",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6", thickness_mm: 223.23501793805622 },
    qty: { target: 50 },
  },
  itar: false,
};

// String length limits count Unicode CODE POINTS (zod v4's `.min`/`.max`), not UTF-16
// code units. part.family here is exactly MAX_NAME (128) code points of U+1F600 — 256
// UTF-16 units. An implementation that counts UTF-16 units (as the Rust core once did)
// refuses this document; both must accept it and hash it identically.
const codePointBoundary: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_cpboundary1",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment" },
  part: {
    family: "\u{1F600}".repeat(128),
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50 },
  },
  itar: false,
};

// A name consisting only of U+0085 (NEL). U+0085 is NOT ECMAScript whitespace, so the
// name is non-blank and the traveler is Quoteable (L0). An implementation that decides
// "blank" with a Unicode White_Space trim (Rust's `str::trim` strips U+0085) calls the
// same document Draft — one document, two levels. Both must say L0.
const nelName: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_nelname001",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "\u0085" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50 },
  },
  itar: false,
};

/** Pretty JSON for a vector file, with C1 control characters written as `\u00XX`
 *  escapes so an invisible character (the U+0085 above) is reviewable in a diff. Both
 *  spellings parse to the same string. */
const wire = (p: unknown): string =>
  JSON.stringify(p, null, 2).replace(
    /[\u0080-\u009f]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ) + "\n";

const expected: Record<string, { traveler_hash: string; level: string }> = {};
for (const [file, p] of [
  ["l0-bracket.json", l0],
  ["l0-longfloat.json", longFloat],
  ["l0-empty-arrays.json", emptyArrays],
  ["l1-quoted.json", l1],
  ["l2-awarded.json", l2],
  ["part-family-128-codepoints.json", codePointBoundary],
  ["l0-nel-name.json", nelName],
] as const) {
  const parsed = parseTraveler(JSON.parse(JSON.stringify(p)));
  expected[file] = { traveler_hash: travelerHash(parsed), level: levelOf(parsed).code };
  writeFileSync(`${here}/travelers/${file}`, wire(p));
}

// Integer-valued floats on the wire (revision 1.0, qty.target 250.0, breaks [100.0,
// 250.0]). Both implementations MUST accept these — JS collapses 250.0->250, and the
// Rust core's lenient integer deserializer accepts an integer-valued float — and hash
// them identically to the all-integer form (the canonicalizer renders N.0 as N). See
// docs/SPEC.md §Canonical JSON / parsing. Authored as literal text because
// JSON.stringify of a JS number would collapse the `.0`.
const intFloatJson = `{
  "spec": "sje/0.1.0",
  "traveler_id": "tvl_conformintf",
  "revision": 1.0,
  "created_at": "2026-09-16T12:00:00.000Z",
  "buyer": { "name": "Northline Equipment" },
  "part": {
    "family": "CNC bracket",
    "part_number": "NL-BRK-4410",
    "material": { "spec": "6061-T6" },
    "qty": { "target": 250.0, "breaks": [100.0, 250.0] }
  },
  "itar": false
}
`;
writeFileSync(`${here}/travelers/l0-intfloat.json`, intFloatJson);
const intFloatParsed = parseTraveler(JSON.parse(intFloatJson));
expected["l0-intfloat.json"] = {
  traveler_hash: travelerHash(intFloatParsed),
  level: levelOf(intFloatParsed).code,
};

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

/* ---------- signed award vector (buyer award authorship + quote-content binding) ---------- */
// A traveler whose award + ship-to are signed by the buyer, with the award bound to the awarded
// quote's content via `award.quote_hash`. Both implementations resolve the award sig's kid to a
// directory entry whose org_id equals buyer.org_id and verify the ML-DSA-87 signature over the
// canonical award body {spec, traveler_id, traveler_hash, award (minus sig), ship_to}, then
// require the awarded quote (qot_conform01 — present and unsigned here, the exact gap case) to be
// on the traveler and to hash to award.quote_hash. A forged award, an altered ship-to, a bumped
// revision, a non-buyer signer, OR a swapped unit price on the awarded quote all fail.
const awardTraveler: Traveler = structuredClone(l2);
awardTraveler.traveler_id = "tvl_award0000001";
awardTraveler.buyer = { ...awardTraveler.buyer, org_id: "org_northline" };
const awardHash = travelerHash(awardTraveler);
for (const q of awardTraveler.quotes ?? []) q.traveler_hash_quoted = awardHash;
// Bind the awarded quote's priced content into the award before signing it, so the buyer's award
// signature commits to the exact priced quote, not merely its id.
const awardedQuote = awardTraveler.quotes!.find((q) => q.quote_id === awardTraveler.award!.quote_id)!;
awardTraveler.award!.quote_hash = quoteContentHash(awardedQuote);
awardTraveler.signatures = [signTraveler(awardTraveler, "northline-2026", northlineKp.secretKey)];
awardTraveler.award!.sig = signAward(awardTraveler, "northline-2026", northlineKp.secretKey);
const signedAwardVector = {
  note:
    "Buyer award authorship + quote-content binding (BEC defense, completeness). Verify the " +
    "directory against root_public_key_hex, resolve the award sig's kid to a directory entry " +
    "whose org_id equals buyer.org_id, verify the ML-DSA-87 signature over the canonical award " +
    "body {spec, traveler_id, traveler_hash, award (minus its own sig), ship_to}, then require " +
    "the awarded quote (by award.quote_id) to be present in quotes and to hash (sha384 of the " +
    "quote minus its own sig) to award.quote_hash. A forged award, an altered ship_to, a bumped " +
    "revision, a non-buyer signer, OR a swapped unit price on the awarded quote all fail. " +
    "Evaluate at at_ms (inside the windows).",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  at_ms: Date.parse("2027-01-01T00:00:00.000Z"),
  directory: directoryVector.directory,
  traveler: awardTraveler,
};
writeFileSync(
  `${here}/signatures/signed-award.json`,
  JSON.stringify(signedAwardVector, null, 2) + "\n",
);
console.log("signed award vector written");

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

/* ---------- envelope shape + tamper vectors (accept and reject, both specs) ---------- */
// The golden vectors above prove both implementations seal and open the SAME bytes. These
// prove they REFUSE the same bytes, and why. Each case is the envelope's JSON text exactly
// as it would arrive, plus who tries to open it:
//
//   accept          shape-valid and opens to plaintext_utf8 (strictness must not over-refuse:
//                   member order and whitespace are not part of the shape; two recipients work)
//   reject / shape  refused by the SHAPE check alone, before any key is used. Most of these
//                   would decrypt successfully if the check were missing — an extra member, a
//                   hex string in the other letter case, a repeated member name, a 16-byte
//                   content key — which is exactly why they are vectors.
//   reject / crypto shape-valid, but must fail to open (tamper, reorder, drop, relabel).
//
// A runner checks the stage, not just the refusal: a "shape" case must fail the shape check
// itself, and a "crypto" case must PASS the shape check and then fail to open.
type EnvCase = {
  name: string;
  why: string;
  kid: string;
  seed_hex: string;
  onetime_seed_hex?: string;
  text: string;
};
const NUL = String.fromCharCode(0);
const BOM = String.fromCharCode(0xfeff);
const plain = new TextEncoder().encode(envPlaintext);
const goldenText = JSON.stringify(envelope);
const fsGoldenText = JSON.stringify(fsEnvelope);
const northSeedHex = bytesToHex(northlineKemSeed);
const summitSeedHex = bytesToHex(summitKemSeed);
const otSeedHex = bytesToHex(prekeySeeds[0]!);
const summitRecipient = recipientByOrg(
  directoryVector.directory,
  "org_summitfab",
  new Date("2027-01-01T00:00:00.000Z"),
)!;
const kidN = envRecipient.kid;
const kidS = summitRecipient.kid;

// Two recipients, deterministic.
const det2 = {
  cek: new Uint8Array(32).fill(0x4a),
  payload_nonce: new Uint8Array(12).fill(0x05),
  coins: [new Uint8Array(32).fill(0x0c), new Uint8Array(32).fill(0x0d)],
  wrap_nonces: [new Uint8Array(12).fill(0x06), new Uint8Array(12).fill(0x07)],
};
const two = sealEnvelopeDeterministic(plain, [envRecipient, summitRecipient], det2);
// The same recipient listed twice: the payload AAD binds [kid, kid], so without a
// uniqueness rule this opens.
const twice = sealEnvelopeDeterministic(plain, [envRecipient, envRecipient], det2);

type Mut = Record<string, unknown> & { recipients: Record<string, unknown>[] };
/** A deep copy of an envelope, edited. */
function edit(base: unknown, f: (e: Mut) => void): string {
  const e = structuredClone(base) as Mut;
  f(e);
  return JSON.stringify(e);
}
/** Flip the lowest bit of the first byte of a lowercase-hex string (stays lowercase hex). */
function flip(hex: string): string {
  const first = (parseInt(hex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0");
  return first + hex.slice(2);
}

/** What a non-conforming sealer would emit: everything as specified except the content
 *  key's length. Re-derived here with the primitives directly (not through the code under
 *  test); the 32-byte form is checked against openEnvelope below, so the 16- and 24-byte
 *  forms are known to be exactly "right KDF, right AAD, wrong key size" — AES-128/192-GCM
 *  under an "AES-256-GCM" label. */
function sealWithKeyBytes(keyBytes: number): string {
  const cek = new Uint8Array(keyBytes).fill(0x2b);
  const payloadNonce = new Uint8Array(12).fill(0x08);
  const wrapNonce = new Uint8Array(12).fill(0x09);
  const aadWrap = utf8ToBytes(`${ENVELOPE_SPEC}${NUL}${ENC_ALG}${NUL}${kidN}`);
  const aadBody = utf8ToBytes(
    canonicalJson({ spec: ENVELOPE_SPEC, enc_alg: ENC_ALG, recipients: [kidN] }),
  );
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(
    hexToBytes(envRecipient.public_key),
    new Uint8Array(32).fill(0x0e),
  );
  const kek = hkdf(sha384, sharedSecret, utf8ToBytes("sje-kek/0.1.0"), aadWrap, 32);
  return JSON.stringify({
    spec: ENVELOPE_SPEC,
    enc_alg: ENC_ALG,
    payload_nonce: bytesToHex(payloadNonce),
    payload: bytesToHex(gcm(cek, payloadNonce, aadBody).encrypt(plain)),
    recipients: [
      {
        kid: kidN,
        kem_ct: bytesToHex(cipherText),
        wrap_nonce: bytesToHex(wrapNonce),
        wrapped_cek: bytesToHex(gcm(kek, wrapNonce, aadWrap).encrypt(cek)),
      },
    ],
  });
}
{
  const control = JSON.parse(sealWithKeyBytes(32)) as Parameters<typeof openEnvelope>[0];
  const opened = openEnvelope(control, kidN, northlineKem.secretKey);
  if (new TextDecoder().decode(opened) !== envPlaintext) {
    throw new Error("vector self-check failed: hand-derived envelope does not open");
  }
}

const N = { kid: kidN, seed_hex: northSeedHex };
const S = { kid: kidS, seed_hex: summitSeedHex };
const F = { kid: kidN, seed_hex: northSeedHex, onetime_seed_hex: otSeedHex };

const envAccept: EnvCase[] = [
  { name: "golden-compact", why: "the golden 0.1.0 envelope as compact JSON", ...N, text: goldenText },
  {
    name: "members-reordered-and-indented",
    why: "member order and whitespace are not part of the shape",
    ...N,
    text: JSON.stringify(
      {
        recipients: envelope.recipients.map((r) => ({
          wrapped_cek: r.wrapped_cek,
          wrap_nonce: r.wrap_nonce,
          kem_ct: r.kem_ct,
          kid: r.kid,
        })),
        payload: envelope.payload,
        payload_nonce: envelope.payload_nonce,
        enc_alg: envelope.enc_alg,
        spec: envelope.spec,
      },
      null,
      2,
    ),
  },
  { name: "two-recipients-first", why: "first of two recipients opens", ...N, text: JSON.stringify(two) },
  { name: "two-recipients-second", why: "second of two recipients opens", ...S, text: JSON.stringify(two) },
  { name: "fs-golden-compact", why: "the golden 0.2.0 envelope as compact JSON", ...F, text: fsGoldenText },
];

const shape = (name: string, why: string, who: Omit<EnvCase, "name" | "why" | "text">, text: string) => ({
  name,
  why,
  stage: "shape" as const,
  ...who,
  text,
});
const crypto_ = (name: string, why: string, who: Omit<EnvCase, "name" | "why" | "text">, text: string) => ({
  name,
  why,
  stage: "crypto" as const,
  ...who,
  text,
});
const up = (h: string) => h.toUpperCase();

const envReject = [
  // ---- shape: would otherwise decrypt ----
  shape("extra-member", "an unknown top-level member; the tags do not cover it", N,
    edit(envelope, (e) => { e.note = "trust me"; })),
  shape("extra-recipient-member", "an unknown member on a recipient entry", N,
    edit(envelope, (e) => { e.recipients[0]!.hint = "x"; })),
  shape("payload-uppercase-hex", "hex must be lowercase: one wire form per envelope", N,
    edit(envelope, (e) => { e.payload = up(e.payload as string); })),
  shape("kem-ct-uppercase-hex", "hex must be lowercase", N,
    edit(envelope, (e) => { e.recipients[0]!.kem_ct = up(e.recipients[0]!.kem_ct as string); })),
  shape("wrapped-cek-uppercase-hex", "hex must be lowercase", N,
    edit(envelope, (e) => { e.recipients[0]!.wrapped_cek = up(e.recipients[0]!.wrapped_cek as string); })),
  shape("duplicate-member-payload", "a repeated member name: a last-wins reader opens the second payload and never reads the first", N,
    goldenText.replace('"payload":', '"payload":"00","payload":')),
  shape("duplicate-member-recipient-kid", "a repeated member name inside a recipient entry", N,
    goldenText.replace('"kid":', '"kid":"0000000000000000","kid":')),
  shape("byte-order-mark", "a UTF-8 byte-order mark before the envelope", N, BOM + goldenText),
  shape("trailing-content", "a second JSON value after the envelope", N, goldenText + " {}"),
  shape("content-key-16-bytes", "a 16-byte content key (AES-128-GCM under the AES-256-GCM label); the wrapped key is not 48 bytes", N,
    sealWithKeyBytes(16)),
  shape("content-key-24-bytes", "a 24-byte content key (AES-192-GCM under the AES-256-GCM label)", N,
    sealWithKeyBytes(24)),
  shape("same-recipient-twice", "the same kid in two recipient entries (the AAD binds [kid, kid], so it opens unless refused)", N,
    JSON.stringify(twice)),
  // ---- shape: malformed outright ----
  shape("missing-enc-alg", "a required member is absent", N,
    edit(envelope, (e) => { delete e.enc_alg; })),
  shape("alg-of-the-other-spec", "enc_alg must be the one that belongs to spec", N,
    edit(envelope, (e) => { e.enc_alg = FS_ENC_ALG; })),
  shape("unknown-spec", "an envelope version this specification does not define", N,
    edit(envelope, (e) => { e.spec = "sje-envelope/0.3.0"; })),
  shape("payload-nonce-13-bytes", "nonces are exactly 12 bytes", N,
    edit(envelope, (e) => { e.payload_nonce = (e.payload_nonce as string) + "00"; })),
  shape("wrap-nonce-11-bytes", "nonces are exactly 12 bytes", N,
    edit(envelope, (e) => { e.recipients[0]!.wrap_nonce = (e.recipients[0]!.wrap_nonce as string).slice(2); })),
  shape("kem-ct-one-byte-short", "an ML-KEM-1024 ciphertext is exactly 1568 bytes", N,
    edit(envelope, (e) => { e.recipients[0]!.kem_ct = (e.recipients[0]!.kem_ct as string).slice(2); })),
  shape("payload-shorter-than-a-tag", "the payload carries at least its 16-byte tag", N,
    edit(envelope, (e) => { e.payload = "00".repeat(15); })),
  shape("payload-odd-length-hex", "hex is whole bytes", N,
    edit(envelope, (e) => { e.payload = (e.payload as string) + "0"; })),
  shape("payload-nonce-null", "null is not a string", N,
    edit(envelope, (e) => { e.payload_nonce = null; })),
  shape("kid-not-hex", "kid is 8 bytes of lowercase hex", { kid: "northline-key-01", seed_hex: northSeedHex },
    edit(envelope, (e) => { e.recipients[0]!.kid = "northline-key-01"; })),
  shape("recipients-empty", "at least one recipient", N,
    edit(envelope, (e) => { e.recipients = []; })),
  shape("recipients-seventeen", "at most 16 recipients", N,
    edit(envelope, (e) => {
      const r = e.recipients[0]!;
      e.recipients = Array.from({ length: 17 }, (_, i) => ({ ...r, kid: i.toString(16).padStart(16, "0") }));
    })),
  shape("recipient-as-array", "a recipient entry written positionally, as an array", N,
    edit(envelope, (e) => {
      const r = e.recipients[0]!;
      (e as Record<string, unknown>).recipients = [[r.kid, r.kem_ct, r.wrap_nonce, r.wrapped_cek]];
    })),
  shape("envelope-as-array", "the envelope itself written as an array", N,
    JSON.stringify([envelope.spec, envelope.enc_alg, envelope.payload_nonce, envelope.payload, envelope.recipients])),
  shape("fs-prekey-id-with-nul", "prekey_id is 1-64 of [A-Za-z0-9._-]; it is concatenated into the key-derivation label", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.prekey_id = `northline-ot-1${NUL}x`; })),
  shape("fs-prekey-id-too-long", "prekey_id is at most 64 characters", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.prekey_id = "p".repeat(65); })),
  shape("fs-recipient-without-prekey-id", "a 0.2.0 recipient must name its one-time prekey", F,
    edit(fsEnvelope, (e) => { delete e.recipients[0]!.prekey_id; })),
  shape("static-recipient-in-fs-envelope", "0.1.0 recipient members under a 0.2.0 spec", F,
    edit(fsEnvelope, (e) => { e.recipients = structuredClone(envelope.recipients) as Record<string, unknown>[]; })),
  // ---- crypto: shape-valid, must not open ----
  crypto_("payload-bit-flipped", "one payload bit changed", N,
    edit(envelope, (e) => { e.payload = flip(e.payload as string); })),
  crypto_("payload-nonce-altered", "a different payload nonce", N,
    edit(envelope, (e) => { e.payload_nonce = flip(e.payload_nonce as string); })),
  crypto_("wrapped-cek-bit-flipped", "one bit of the wrapped content key changed", N,
    edit(envelope, (e) => { e.recipients[0]!.wrapped_cek = flip(e.recipients[0]!.wrapped_cek as string); })),
  crypto_("kem-ct-bit-flipped", "one bit of the ML-KEM ciphertext changed (implicit rejection, then the wrap tag fails)", N,
    edit(envelope, (e) => { e.recipients[0]!.kem_ct = flip(e.recipients[0]!.kem_ct as string); })),
  crypto_("two-recipients-reordered", "the payload AAD binds the ORDERED recipient set", N,
    edit(two, (e) => { e.recipients.reverse(); })),
  crypto_("two-recipients-one-dropped", "the payload AAD binds the WHOLE recipient set", N,
    edit(two, (e) => { e.recipients = [e.recipients[0]!]; })),
  crypto_("two-recipients-one-dropped-other-side", "the remaining recipient cannot open either", S,
    edit(two, (e) => { e.recipients = [e.recipients[1]!]; })),
  crypto_("two-recipients-keys-swapped", "each wrapped key is bound to its own kid", N,
    edit(two, (e) => {
      const [a, b] = [e.recipients[0]!, e.recipients[1]!];
      [a.wrapped_cek, b.wrapped_cek] = [b.wrapped_cek, a.wrapped_cek];
    })),
  crypto_("recipient-relabelled", "an entry sealed for one kid, relabelled with another's kid", S,
    edit(envelope, (e) => { e.recipients[0]!.kid = kidS; })),
  crypto_("fs-prekey-id-relabelled", "prekey_id is bound into the key derivation and the payload AAD", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.prekey_id = "northline-ot-2"; })),
  crypto_("fs-onetime-ct-bit-flipped", "one bit of the one-time ciphertext changed", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.kem_ct_onetime = flip(e.recipients[0]!.kem_ct_onetime as string); })),
  crypto_("fs-static-ct-bit-flipped", "one bit of the static ciphertext changed", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.kem_ct_static = flip(e.recipients[0]!.kem_ct_static as string); })),
  crypto_("fs-payload-bit-flipped", "one payload bit changed", F,
    edit(fsEnvelope, (e) => { e.payload = flip(e.payload as string); })),
];

const envelopeCases = {
  note:
    "Envelope accept/reject cases for both envelope specs. `text` is the envelope's JSON text " +
    "exactly as on the wire; `kid`/`seed_hex` (and `onetime_seed_hex` for 0.2.0) say who opens it. " +
    "accept: MUST pass the shape check and open to plaintext_utf8. reject with stage \"shape\": MUST " +
    "be refused by the shape check alone, before any key is used. reject with stage \"crypto\": MUST " +
    "pass the shape check and MUST fail to open. See docs/ENVELOPE-DRAFT.md (Wire shape).",
  plaintext_utf8: envPlaintext,
  accept: envAccept,
  reject: envReject,
};
// Written with every non-ASCII character escaped, so the byte-order mark in one case is
// visible in a diff instead of an invisible character in the file.
writeFileSync(
  `${here}/signatures/envelope-cases.json`,
  JSON.stringify(envelopeCases, null, 2).replace(
    /[^\n -~]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ) + "\n",
);
console.log(`envelope cases written (${envAccept.length} accept, ${envReject.length} reject)`);
