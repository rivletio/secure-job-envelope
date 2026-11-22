/** Trust-root fingerprints — the form of a root a person can actually compare.
 *
 *  A trust root is an ML-DSA-87 public key: 2,592 bytes, 5,184 hex characters. Nobody
 *  reads that over a phone or checks it by eye, so "verify the root out of band" was a
 *  step that got skipped — and whoever supplies the root supplies every verdict the
 *  desk will ever show. The fingerprint is what gets compared instead:
 *
 *    SHA-384 over the raw public-key bytes, lowercase hex,
 *    the first 32 hex characters (128 bits), in groups of four.
 *
 *  Everything here works on the key's BYTES, never on its hex text: `ABCD…` and
 *  `abcd…` are the same key, verify the same directory, and must have the same
 *  identity — otherwise re-casing a root would make it look like a different one.
 */
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "./bytes.ts";

const HEX_BYTES = /^(?:[0-9a-fA-F]{2})+$/;

/** Shown where a fingerprint would be when the value is not a key at all. */
export const NO_FINGERPRINT = "(not a public key)";

/** A root's identity: SHA-384 of its raw public-key bytes, as 96 lowercase hex
 *  characters — or null if `rootPublicKeyHex` is not hex-encoded bytes. Two roots are
 *  the same root iff this is equal. */
export function rootDigest(rootPublicKeyHex: unknown): string | null {
  if (typeof rootPublicKeyHex !== "string" || !HEX_BYTES.test(rootPublicKeyHex)) return null;
  return bytesToHex(sha384(hexToBytes(rootPublicKeyHex)));
}

/** The short fingerprint of a trust-root public key, e.g.
 *  `cb00 753f 45a3 5e8b b5a0 3d69 9ac6 5007`: the first 32 hex characters of
 *  `rootDigest`, grouped in fours. Never throws — a value that is not a key yields
 *  `NO_FINGERPRINT`, which cannot be mistaken for one. */
export function rootFingerprint(rootPublicKeyHex: unknown): string {
  const digest = rootDigest(rootPublicKeyHex);
  return digest === null ? NO_FINGERPRINT : formatFingerprint(digest);
}

/** The short, grouped form of a full root digest (as returned by `rootDigest`). */
export function formatFingerprint(digest: string): string {
  return (digest.slice(0, 32).match(/.{1,4}/g) ?? []).join(" ");
}

/** True iff both values are hex encodings of the same key bytes. */
export function sameRoot(a: unknown, b: unknown): boolean {
  const da = rootDigest(a);
  return da !== null && da === rootDigest(b);
}
