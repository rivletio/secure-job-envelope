/** Confidentiality — the encrypted envelope (CNSA 2.0 profile).
 *
 *  Suite: ML-KEM-1024 (FIPS 203) key encapsulation, HKDF-SHA-384 key derivation,
 *  AES-256-GCM authenticated encryption. A random content-encryption key (CEK)
 *  encrypts the payload once; per recipient, an ML-KEM encapsulation yields a
 *  shared secret, HKDF derives a key-encryption key (KEK), and the CEK is wrapped
 *  under it. Additional authenticated data binds {spec, enc_alg} to the payload
 *  and {spec, enc_alg, kid} to each wrap, so a stripped or swapped field breaks
 *  the tag.
 *
 *  Determinism: pass a `SealDeterminism` (fixed CEK / nonces / KEM coins) to get
 *  byte-reproducible envelopes for the cross-language golden vectors; omit it for
 *  real sealing, which draws all randomness from a CSPRNG.
 */
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes } from "./signature.ts";

export const ENVELOPE_SPEC = "sje-envelope/0.1.0" as const;
export const ENC_ALG = "ML-KEM-1024+HKDF-SHA-384+AES-256-GCM" as const;
const KEK_SALT = new TextEncoder().encode("sje-kek/0.1.0");

function aadPayload(): Uint8Array {
  return new TextEncoder().encode(`${ENVELOPE_SPEC}\u0000${ENC_ALG}`);
}
function aadRecipient(kid: string): Uint8Array {
  return new TextEncoder().encode(`${ENVELOPE_SPEC}\u0000${ENC_ALG}\u0000${kid}`);
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

export function sealEnvelope(
  plaintext: Uint8Array,
  recipients: SealRecipient[],
  det?: Partial<SealDeterminism>,
): Envelope {
  if (recipients.length === 0) throw new Error("at least one recipient is required");
  const cek = det?.cek ?? randomBytes(32);
  const payloadNonce = det?.payload_nonce ?? randomBytes(12);
  const payload = gcm(cek, payloadNonce, aadPayload()).encrypt(plaintext);
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

/** Decrypt an envelope with the recipient's ML-KEM-1024 secret key. Throws on any
 *  failure (unknown kid, tag mismatch), never returning partial plaintext. */
export function openEnvelope(env: Envelope, kid: string, secretKey: Uint8Array): Uint8Array {
  if (env.spec !== ENVELOPE_SPEC || env.enc_alg !== ENC_ALG) {
    throw new Error("unsupported envelope spec/alg");
  }
  const r = env.recipients.find((x) => x.kid === kid);
  if (!r) throw new Error("no recipient entry for this kid");
  const sharedSecret = ml_kem1024.decapsulate(hexToBytes(r.kem_ct), secretKey);
  const cek = gcm(kek(sharedSecret, kid), hexToBytes(r.wrap_nonce), aadRecipient(kid)).decrypt(
    hexToBytes(r.wrapped_cek),
  );
  return gcm(cek, hexToBytes(env.payload_nonce), aadPayload()).decrypt(hexToBytes(env.payload));
}
