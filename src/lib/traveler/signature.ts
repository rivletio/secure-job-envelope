/** Post-quantum authorship signatures (CNSA 2.0 profile: ML-DSA-87, FIPS 204).
 *
 *  A signature is taken over the *domain-separated canonical bytes* of a body —
 *  the exact input the content hash is computed from — so a valid signature
 *  proves who authored the traveler / quote / directory, not merely that some
 *  ciphertext was wrapped. This is the missing half of 0.0.1: the hash is
 *  integrity; this is authenticity.
 *
 *  Determinism: ML-DSA is signed with the FIPS 204 deterministic variant
 *  (rnd = 32 zero bytes, via `{ extraEntropy: false }`) so the same (key, body)
 *  yields byte-identical signatures — a hard requirement for the cross-language
 *  golden vectors that the Rust implementation verifies independently.
 */
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

export const SIG_ALG = "ML-DSA-87" as const;

/** Domain tags bind a signature to its role, so a signature over one kind of
 *  body can never be replayed as another (e.g. a quote signature accepted as a
 *  directory signature). The tag is part of the signed bytes. */
export const SIG_DOMAIN = {
  traveler: "sje-sig/traveler/0.1.0",
  quote: "sje-sig/quote/0.1.0",
  directory: "sje-sig/directory/0.1.0",
} as const;

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0 || /[^0-9a-f]/i.test(h)) throw new Error("invalid hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Bytes actually signed: the domain tag, a NUL, then the canonical body. */
function signedMessage(domain: string, canonicalBody: string): Uint8Array {
  return utf8(`${domain}\u0000${canonicalBody}`);
}

export type Keypair = { publicKey: Uint8Array; secretKey: Uint8Array };

/** Deterministic keypair from a 32-byte seed. Real deployments generate a seed
 *  from a CSPRNG and never share the secret key; fixed seeds drive test vectors. */
export function keypairFromSeed(seed: Uint8Array): Keypair {
  if (seed.length !== 32) throw new Error("ML-DSA-87 seed must be 32 bytes");
  return ml_dsa87.keygen(seed);
}

/** Deterministic ML-DSA-87 signature (lowercase hex) over the domain-separated body. */
export function signBody(domain: string, canonicalBody: string, secretKey: Uint8Array): string {
  const sig = ml_dsa87.sign(signedMessage(domain, canonicalBody), secretKey, {
    extraEntropy: false,
  });
  return bytesToHex(sig);
}

export function verifyBody(
  domain: string,
  canonicalBody: string,
  sigHex: string,
  publicKey: Uint8Array,
): boolean {
  try {
    return ml_dsa87.verify(hexToBytes(sigHex), signedMessage(domain, canonicalBody), publicKey);
  } catch {
    return false;
  }
}
