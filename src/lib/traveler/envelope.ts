/** Confidentiality — the encrypted envelope (CNSA 2.0 profile).
 *
 *  Suite: ML-KEM-1024 (FIPS 203) key encapsulation, HKDF-SHA-384 key derivation,
 *  AES-256-GCM authenticated encryption. A random content-encryption key (CEK)
 *  encrypts the payload once; per recipient, an ML-KEM encapsulation yields a
 *  shared secret, HKDF derives a key-encryption key (KEK), and the CEK is wrapped
 *  under it. Additional authenticated data binds {spec, enc_alg, recipient set}
 *  to the payload and {spec, enc_alg, kid} to each wrap, so a stripped, swapped,
 *  reordered, or dropped field/recipient breaks the tag.
 *
 *  Recipient keys: prefer resolving recipients through the signed directory
 *  (`recipientByOrg`), which binds an ML-KEM public key to an org via the trust
 *  root, over passing raw caller-supplied bytes to `sealEnvelope` — that closes
 *  the "sealer encrypts to an attacker-substituted key" gap.
 *
 *  Determinism: production sealing (`sealEnvelope`) always draws randomness from a
 *  CSPRNG. Byte-reproducible envelopes for the cross-language golden vectors come
 *  from the separate `sealEnvelopeDeterministic`, which is test/vector-only.
 */
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "./bytes.ts";
import { canonicalJson } from "./canonical.ts";
import { entryByOrg, type Directory } from "./directory.ts";
import { verifyPrekeyBundle, prekeyById, type PrekeyBundle } from "./prekeys.ts";

export const ENVELOPE_SPEC = "sje-envelope/0.1.0" as const;
export const ENC_ALG = "ML-KEM-1024+HKDF-SHA-384+AES-256-GCM" as const;
/** The KEM component, as attested in a directory entry's `enc_alg`. */
export const KEM_ALG = "ML-KEM-1024" as const;
const KEK_SALT = utf8ToBytes("sje-kek/0.1.0");

/** Payload AAD binds the algorithm identifiers AND the ordered recipient set, so
 *  a downgraded alg or a dropped/reordered/duplicated recipient entry fails the
 *  payload tag on open. Recipient kids are already in the clear in the envelope,
 *  so binding them adds no metadata. */
function aadPayload(recipientKids: string[]): Uint8Array {
  return utf8ToBytes(
    canonicalJson({ spec: ENVELOPE_SPEC, enc_alg: ENC_ALG, recipients: recipientKids }),
  );
}
function aadRecipient(kid: string): Uint8Array {
  return utf8ToBytes(`${ENVELOPE_SPEC}\u0000${ENC_ALG}\u0000${kid}`);
}
function kek(sharedSecret: Uint8Array, kid: string): Uint8Array {
  return hkdf(sha384, sharedSecret, KEK_SALT, aadRecipient(kid), 32);
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("a secure random source (crypto.getRandomValues) is required to seal");
  }
  crypto.getRandomValues(b);
  return b;
}

export type EnvelopeRecipient = {
  kid: string;
  kem_ct: string; // hex ML-KEM-1024 ciphertext
  wrap_nonce: string; // hex 12-byte nonce
  wrapped_cek: string; // hex AES-256-GCM(CEK) incl tag
};
export type Envelope = {
  spec: typeof ENVELOPE_SPEC;
  enc_alg: typeof ENC_ALG;
  payload_nonce: string; // hex 12-byte nonce
  payload: string; // hex AES-256-GCM(payload) incl tag
  recipients: EnvelopeRecipient[];
};

export type SealRecipient = { kid: string; public_key: string }; // hex ML-KEM ek
export type SealDeterminism = {
  cek: Uint8Array; // 32
  payload_nonce: Uint8Array; // 12
  coins: Uint8Array[]; // 32 per recipient (ML-KEM message randomness)
  wrap_nonces: Uint8Array[]; // 12 per recipient
};

/** ML-KEM-1024 keypair from a 64-byte seed (d‖z). */
export function kemKeypairFromSeed(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  if (seed.length !== 64) throw new Error("ML-KEM-1024 seed must be 64 bytes");
  return ml_kem1024.keygen(seed);
}

/** Opaque recipient id derived from an ML-KEM public key: the first 16 hex chars
 *  (8 bytes) of its SHA-384. It leaks no org identity (metadata minimization) yet
 *  binds the kid to the key, so a recipient entry cannot be silently pointed at a
 *  different key. */
export function encKid(encPublicKeyHex: string): string {
  return bytesToHex(sha384(hexToBytes(encPublicKeyHex))).slice(0, 16);
}

/** Resolve a recipient from the signed directory: the attested, in-window ML-KEM
 *  key for an org, keyed by its derived enc kid. Prefer this over caller-supplied
 *  bytes so a sealer encrypts to a key the trust root bound to the org, not to
 *  whatever bytes an attacker substituted out of band. Returns undefined if the
 *  org has no in-window entry carrying an ML-KEM-1024 key. The caller must first
 *  verify the directory against the trust root (verifyDirectory). */
export function recipientByOrg(dir: Directory, orgId: string, at?: Date): SealRecipient | undefined {
  const e = entryByOrg(dir, orgId, at);
  if (!e || e.enc_alg !== KEM_ALG || !e.enc_public_key) return undefined;
  return { kid: encKid(e.enc_public_key), public_key: e.enc_public_key };
}

function seal(
  plaintext: Uint8Array,
  recipients: SealRecipient[],
  det?: Partial<SealDeterminism>,
): Envelope {
  if (recipients.length === 0) throw new Error("at least one recipient is required");
  const kids = recipients.map((r) => r.kid);
  const cek = det?.cek ?? randomBytes(32);
  const payloadNonce = det?.payload_nonce ?? randomBytes(12);
  const payload = gcm(cek, payloadNonce, aadPayload(kids)).encrypt(plaintext);
  const recips = recipients.map((r, i) => {
    const coins = det?.coins?.[i] ?? randomBytes(32);
    const wrapNonce = det?.wrap_nonces?.[i] ?? randomBytes(12);
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(hexToBytes(r.public_key), coins);
    const wrapped = gcm(kek(sharedSecret, r.kid), wrapNonce, aadRecipient(r.kid)).encrypt(cek);
    return {
      kid: r.kid,
      kem_ct: bytesToHex(cipherText),
      wrap_nonce: bytesToHex(wrapNonce),
      wrapped_cek: bytesToHex(wrapped),
    };
  });
  return {
    spec: ENVELOPE_SPEC,
    enc_alg: ENC_ALG,
    payload_nonce: bytesToHex(payloadNonce),
    payload: bytesToHex(payload),
    recipients: recips,
  };
}

/** Seal a payload to one or more recipients. All randomness (CEK, nonces, KEM
 *  coins) is drawn from a CSPRNG; there is no way to pin it, so a caller cannot
 *  accidentally reuse a CEK across envelopes. */
export function sealEnvelope(plaintext: Uint8Array, recipients: SealRecipient[]): Envelope {
  return seal(plaintext, recipients);
}

/** Test/vector-only: seal with a fixed CEK / nonces / KEM coins to produce a
 *  byte-reproducible envelope for the cross-language golden vectors. Never use in
 *  production — pinning the CEK across envelopes would let a wrapped-CEK swap
 *  recover the key. */
export function sealEnvelopeDeterministic(
  plaintext: Uint8Array,
  recipients: SealRecipient[],
  det: SealDeterminism,
): Envelope {
  return seal(plaintext, recipients, det);
}

/** Decrypt an envelope with the recipient's ML-KEM-1024 secret key. Throws on any
 *  failure (unknown kid, tag mismatch, tampered recipient set), never returning
 *  partial plaintext. */
export function openEnvelope(env: Envelope, kid: string, secretKey: Uint8Array): Uint8Array {
  if (env.spec !== ENVELOPE_SPEC || env.enc_alg !== ENC_ALG) {
    throw new Error("unsupported envelope spec/alg");
  }
  const r = env.recipients.find((x) => x.kid === kid);
  if (!r) throw new Error("no recipient entry for this kid");
  // Filter to string kids so the AAD matches the Rust verifier's filter_map
  // byte for byte on a malformed envelope (a recipient with no kid). A legitimate
  // envelope's recipients all carry string kids, so this is a no-op there.
  const kids = env.recipients.map((x) => x.kid).filter((k): k is string => typeof k === "string");
  const sharedSecret = ml_kem1024.decapsulate(hexToBytes(r.kem_ct), secretKey);
  const cek = gcm(kek(sharedSecret, kid), hexToBytes(r.wrap_nonce), aadRecipient(kid)).decrypt(
    hexToBytes(r.wrapped_cek),
  );
  return gcm(cek, hexToBytes(env.payload_nonce), aadPayload(kids)).decrypt(hexToBytes(env.payload));
}

/* ---------------------------------------------------------------------------
 * Forward-secret envelope (sje-envelope/0.2.0) — single-use prekeys, PQXDH-style.
 *
 * The 0.1 envelope above encapsulates only to a recipient's long-lived (static)
 * ML-KEM key, so a later compromise of that key exposes every stored envelope.
 * This variant additionally encapsulates to a *one-time* prekey from the
 * recipient's signed bundle (prekeys.ts) and binds BOTH shared secrets into the
 * KEK. After the recipient decrypts and deletes the one-time secret, a later
 * compromise of the static key can no longer recover the message — forward
 * secrecy. Conversely, if a one-time prekey is ever reused or mishandled, the
 * static half still keeps the payload confidential (graceful degradation).
 *
 * Realizing forward secrecy requires the recipient to delete the consumed
 * one-time secret; the format enables it, key management completes it.
 * ------------------------------------------------------------------------- */

export const FS_ENVELOPE_SPEC = "sje-envelope/0.2.0" as const;
export const FS_ENC_ALG = "ML-KEM-1024x2+HKDF-SHA-384+AES-256-GCM" as const;

function aadPayloadFs(recipients: { kid: string; prekey_id: string }[]): Uint8Array {
  return utf8ToBytes(canonicalJson({ spec: FS_ENVELOPE_SPEC, enc_alg: FS_ENC_ALG, recipients }));
}
function aadRecipientFs(kid: string, prekeyId: string): Uint8Array {
  return utf8ToBytes(`${FS_ENVELOPE_SPEC}\u0000${FS_ENC_ALG}\u0000${kid}\u0000${prekeyId}`);
}
/** KEK derived from BOTH shared secrets (one-time ‖ static). Order is fixed and
 *  must match the Rust implementation. */
function fsKek(ssOnetime: Uint8Array, ssStatic: Uint8Array, kid: string, prekeyId: string): Uint8Array {
  const ikm = new Uint8Array(ssOnetime.length + ssStatic.length);
  ikm.set(ssOnetime, 0);
  ikm.set(ssStatic, ssOnetime.length);
  return hkdf(sha384, ikm, KEK_SALT, aadRecipientFs(kid, prekeyId), 32);
}

export type FsEnvelopeRecipient = {
  kid: string; // enc_kid of the recipient's STATIC identity key (as in 0.1)
  prekey_id: string; // which one-time prekey was used
  kem_ct_onetime: string; // hex ML-KEM ct to the one-time prekey
  kem_ct_static: string; // hex ML-KEM ct to the static identity key
  wrap_nonce: string;
  wrapped_cek: string;
};
export type FsEnvelope = {
  spec: typeof FS_ENVELOPE_SPEC;
  enc_alg: typeof FS_ENC_ALG;
  payload_nonce: string;
  payload: string;
  recipients: FsEnvelopeRecipient[];
};

export type FsSealRecipient = {
  kid: string; // static enc_kid
  static_public_key: string; // hex ML-KEM identity ek
  prekey_id: string;
  onetime_public_key: string; // hex ML-KEM one-time ek
};
export type FsSealDeterminism = {
  cek: Uint8Array; // 32
  payload_nonce: Uint8Array; // 12
  coins_onetime: Uint8Array[]; // 32 per recipient
  coins_static: Uint8Array[]; // 32 per recipient
  wrap_nonces: Uint8Array[]; // 12 per recipient
};

/** Resolve a forward-secret recipient: the static ML-KEM key from the signed
 *  directory (recipientByOrg) plus one verified one-time prekey from the org's
 *  signed bundle. Returns undefined unless the org has an attested static key AND
 *  the bundle verifies (against the same root) AND carries `prekeyId`. Prefer this
 *  over hand-assembling a recipient from raw bytes. */
export function fsRecipientFromBundle(
  dir: Directory,
  bundle: PrekeyBundle,
  orgId: string,
  prekeyId: string,
  rootPublicKeyHex: string,
  at?: Date,
): FsSealRecipient | undefined {
  const staticR = recipientByOrg(dir, orgId, at);
  if (!staticR) return undefined;
  const vetted = verifyPrekeyBundle(bundle, dir, rootPublicKeyHex, at);
  if (!vetted || vetted.org_id !== orgId) return undefined;
  const pk = prekeyById(vetted, prekeyId);
  if (!pk) return undefined;
  return {
    kid: staticR.kid,
    static_public_key: staticR.public_key,
    prekey_id: prekeyId,
    onetime_public_key: pk.public_key,
  };
}

function sealFs(
  plaintext: Uint8Array,
  recipients: FsSealRecipient[],
  det?: Partial<FsSealDeterminism>,
): FsEnvelope {
  if (recipients.length === 0) throw new Error("at least one recipient is required");
  const rset = recipients.map((r) => ({ kid: r.kid, prekey_id: r.prekey_id }));
  const cek = det?.cek ?? randomBytes(32);
  const payloadNonce = det?.payload_nonce ?? randomBytes(12);
  const payload = gcm(cek, payloadNonce, aadPayloadFs(rset)).encrypt(plaintext);
  const recips = recipients.map((r, i) => {
    const coinsOt = det?.coins_onetime?.[i] ?? randomBytes(32);
    const coinsId = det?.coins_static?.[i] ?? randomBytes(32);
    const wrapNonce = det?.wrap_nonces?.[i] ?? randomBytes(12);
    const ot = ml_kem1024.encapsulate(hexToBytes(r.onetime_public_key), coinsOt);
    const id = ml_kem1024.encapsulate(hexToBytes(r.static_public_key), coinsId);
    const kek = fsKek(ot.sharedSecret, id.sharedSecret, r.kid, r.prekey_id);
    const wrapped = gcm(kek, wrapNonce, aadRecipientFs(r.kid, r.prekey_id)).encrypt(cek);
    return {
      kid: r.kid,
      prekey_id: r.prekey_id,
      kem_ct_onetime: bytesToHex(ot.cipherText),
      kem_ct_static: bytesToHex(id.cipherText),
      wrap_nonce: bytesToHex(wrapNonce),
      wrapped_cek: bytesToHex(wrapped),
    };
  });
  return {
    spec: FS_ENVELOPE_SPEC,
    enc_alg: FS_ENC_ALG,
    payload_nonce: bytesToHex(payloadNonce),
    payload: bytesToHex(payload),
    recipients: recips,
  };
}

/** Seal a forward-secret envelope. All randomness is drawn from a CSPRNG. Each
 *  recipient's one-time prekey should be used at most once and its secret deleted
 *  after the recipient opens it. */
export function sealFsEnvelope(plaintext: Uint8Array, recipients: FsSealRecipient[]): FsEnvelope {
  return sealFs(plaintext, recipients);
}

/** Test/vector-only deterministic forward-secret seal. */
export function sealFsEnvelopeDeterministic(
  plaintext: Uint8Array,
  recipients: FsSealRecipient[],
  det: FsSealDeterminism,
): FsEnvelope {
  return sealFs(plaintext, recipients, det);
}

/** Open a forward-secret envelope. Requires BOTH the recipient's static identity
 *  secret key and the one-time prekey secret named by the recipient entry — the
 *  one-time secret is what the recipient deletes to realize forward secrecy.
 *  Throws on any failure (unknown kid, tag mismatch, tampered recipient set). */
export function openFsEnvelope(
  env: FsEnvelope,
  kid: string,
  staticSecretKey: Uint8Array,
  onetimeSecretKey: Uint8Array,
): Uint8Array {
  if (env.spec !== FS_ENVELOPE_SPEC || env.enc_alg !== FS_ENC_ALG) {
    throw new Error("unsupported envelope spec/alg");
  }
  const r = env.recipients.find((x) => x.kid === kid);
  if (!r) throw new Error("no recipient entry for this kid");
  // Filter to string kids to match the Rust verifier's filter_map on a malformed
  // envelope (no-op for a well-formed one — every recipient carries a string kid).
  const rset = env.recipients
    .filter((x) => typeof x.kid === "string")
    .map((x) => ({ kid: x.kid, prekey_id: x.prekey_id }));
  const ssOt = ml_kem1024.decapsulate(hexToBytes(r.kem_ct_onetime), onetimeSecretKey);
  const ssId = ml_kem1024.decapsulate(hexToBytes(r.kem_ct_static), staticSecretKey);
  const kek = fsKek(ssOt, ssId, kid, r.prekey_id);
  const cek = gcm(kek, hexToBytes(r.wrap_nonce), aadRecipientFs(kid, r.prekey_id)).decrypt(
    hexToBytes(r.wrapped_cek),
  );
  return gcm(cek, hexToBytes(env.payload_nonce), aadPayloadFs(rset)).decrypt(hexToBytes(env.payload));
}
