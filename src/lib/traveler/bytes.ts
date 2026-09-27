/** Byte / hex / UTF-8 helpers, sourced from @noble/hashes.
 *
 *  These are re-exported from a dependency the crypto already relies on, rather
 *  than hand-rolled, so there is one audited implementation of each. Keeping them
 *  here (not in signature.ts) lets the confidentiality module (envelope.ts) and
 *  the authenticity module (signature.ts) share them without depending on each
 *  other.
 */
export { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
