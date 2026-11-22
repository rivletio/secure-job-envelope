/** Byte / hex / UTF-8 helpers, sourced from @noble/hashes.
 *
 *  These are re-exported from a dependency the crypto already relies on, rather
 *  than hand-rolled, so there is one audited implementation of each. Keeping them
 *  here (not in signature.ts) lets the confidentiality module (envelope.ts) and
 *  the authenticity module (signature.ts) share them without depending on each
 *  other.
 */
export { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/** Fill `n` bytes from the platform CSPRNG. Throws rather than ever falling back to a
 *  non-cryptographic source: every key, nonce, salt, and random filename in the crypto
 *  modules draws from here, so a single place enforces the "no insecure fallback" rule.
 *  (ids.ts keeps its own rejection-sampling variant for unbiased id characters.) */
export function randomBytes(n: number): Uint8Array {
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("a secure random source (crypto.getRandomValues) is required");
  }
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
