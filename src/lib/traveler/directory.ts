/** Signed key directory — the trust root the signatures stand on.
 *
 *  A KEM or a signature is only as good as the binding from a key to a real
 *  party. The directory maps org_id -> key (kid, ML-DSA-87 public key) with a
 *  validity window, a revocation status, and attested capabilities (e.g. ITAR
 *  eligibility). The whole directory is itself signed by a trust root whose
 *  public key is distributed out of band, so a verifier that trusts the root
 *  can trust every entry — and org_id spoofing (caveat 2) and self-declared
 *  ITAR (caveat 3) become attested facts rather than free-text claims.
 */
import { canonicalJson } from "./canonical.ts";
import { isoDateTimeMs } from "./datetime.ts";
import { SIG_DOMAIN, SIG_ALG, signBody, verifyBody } from "./signature.ts";
import { hexToBytes } from "./bytes.ts";
import { parseStrictJson } from "./wire.ts";

export const DIRECTORY_SPEC = "sje-directory/0.1.0" as const;
/** Most entries one directory may carry. */
export const MAX_DIRECTORY_ENTRIES = 512;
/** A directory's JSON text, in UTF-8 bytes (an entry is ~9 KB of key material). */
export const MAX_DIRECTORY_JSON_BYTES = 8 * 1024 * 1024;
/** The key-encapsulation algorithm an entry may attest (envelope.ts KEM_ALG). */
const DIRECTORY_KEM_ALG = "ML-KEM-1024";

// Exact sizes of the key material this version of the format carries.
export const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
export const ML_DSA_87_SIGNATURE_BYTES = 4627;
export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;

export const ORG_ID_RE = /^[a-z][a-z0-9_]{1,63}$/;
/** Key ids, root ids and prekey ids: short, printable, no separators. */
export const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const LOWER_HEX = /^[0-9a-f]*$/;

/** True iff `v` is lowercase hex of exactly `bytes` bytes. */
export function isHexOf(v: unknown, bytes: number): v is string {
  return typeof v === "string" && v.length === 2 * bytes && LOWER_HEX.test(v);
}
/** True iff `v` is a plain object whose members are all in `required ∪ optional` and
 *  include every one of `required`. */
export function hasMembers(
  v: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  return (
    required.every((m) => Object.hasOwn(v, m)) &&
    keys.every((k) => required.includes(k) || optional.includes(k))
  );
}
/** `[from, until)` as instants, or null unless both are canonical datetimes in order. */
export function windowOf(from: unknown, until: unknown): { from: number; until: number } | null {
  if (typeof from !== "string" || typeof until !== "string") return null;
  const a = isoDateTimeMs(from);
  const b = isoDateTimeMs(until);
  return a !== null && b !== null && a < b ? { from: a, until: b } : null;
}

export type DirectoryEntry = {
  org_id: string;
  kid: string;
  alg: string;
  public_key: string; // lowercase hex ML-DSA-87 signing (verify) key
  valid_from: string;
  valid_until: string;
  status: "active" | "revoked";
  capabilities?: { itar?: boolean };
  enc_alg?: string; // e.g. "ML-KEM-1024" — the attested encryption-key algorithm
  enc_public_key?: string; // lowercase hex ML-KEM public key, if the org accepts sealed envelopes
};

export type Directory = {
  spec: typeof DIRECTORY_SPEC;
  issued_at: string;
  valid_until: string;
  root_kid: string;
  entries: DirectoryEntry[];
  sig?: string; // hex ML-DSA-87 signature by the root over the canonical body
};

/** The canonical bytes the root signs: the directory without its own signature. */
export function directoryBody(dir: Directory): string {
  const { sig: _omit, ...body } = dir;
  void _omit;
  return canonicalJson(body);
}

export function signDirectory(dir: Directory, rootSecretKey: Uint8Array): string {
  return signBody(SIG_DOMAIN.directory, directoryBody(dir), rootSecretKey);
}

/** Why `dir` is not a well-formed signed directory, or null if it is.
 *
 *  The root's signature says the root signed these bytes; it does not say the bytes
 *  mean anything. A root-signed directory with `entries: [null]`, a capability spelled
 *  `"itar": "false"`, the same kid on two orgs, or a key of the wrong length used to be
 *  read by each implementation in its own way (this one threw on the first, granted ITAR
 *  on the second, and took whichever entry came first on the third). So the shape is
 *  exact, and identical in the Rust core (`sign.rs` `directory_shape`):
 *
 *    directory  exactly { spec, issued_at, valid_until, root_kid, entries, sig }
 *    entry      { org_id, kid, alg, public_key, valid_from, valid_until, status } and
 *               optionally { capabilities, enc_alg, enc_public_key }; nothing else
 *    ids        org_id as in a traveler; kid / root_kid 1–64 of [A-Za-z0-9._-];
 *               no kid on two entries
 *    keys       alg "ML-DSA-87" with a 2592-byte key; enc_alg "ML-KEM-1024" with a
 *               1568-byte key, both or neither; the signature 4627 bytes; lowercase hex
 *    windows    canonical UTC datetimes, start strictly before end
 *    status     "active" | "revoked";  capabilities  {} or { itar: boolean }
 *    entries    at most 512 */
export function directoryShapeError(dir: unknown): string | null {
  if (!hasMembers(dir, ["spec", "issued_at", "valid_until", "root_kid", "entries", "sig"])) {
    return "unexpected or missing members";
  }
  if (dir.spec !== DIRECTORY_SPEC) return "unsupported spec";
  if (!windowOf(dir.issued_at, dir.valid_until)) return "issued_at / valid_until";
  if (typeof dir.root_kid !== "string" || !KEY_ID_RE.test(dir.root_kid)) return "root_kid";
  if (!isHexOf(dir.sig, ML_DSA_87_SIGNATURE_BYTES)) return "sig";
  const entries = dir.entries;
  if (!Array.isArray(entries) || entries.length > MAX_DIRECTORY_ENTRIES) return "entries";
  const kids = new Set<string>();
  for (const [i, e] of entries.entries()) {
    const at = `entries[${i}]`;
    if (
      !hasMembers(
        e,
        ["org_id", "kid", "alg", "public_key", "valid_from", "valid_until", "status"],
        ["capabilities", "enc_alg", "enc_public_key"],
      )
    ) {
      return `${at} has unexpected or missing members`;
    }
    if (typeof e.org_id !== "string" || !ORG_ID_RE.test(e.org_id)) return `${at}.org_id`;
    if (typeof e.kid !== "string" || !KEY_ID_RE.test(e.kid)) return `${at}.kid`;
    if (kids.has(e.kid)) return `${at}.kid repeats an earlier entry`;
    kids.add(e.kid);
    if (e.alg !== SIG_ALG) return `${at}.alg`;
    if (!isHexOf(e.public_key, ML_DSA_87_PUBLIC_KEY_BYTES)) return `${at}.public_key`;
    if (!windowOf(e.valid_from, e.valid_until)) return `${at}.valid_from / valid_until`;
    if (e.status !== "active" && e.status !== "revoked") return `${at}.status`;
    if (Object.hasOwn(e, "capabilities")) {
      const c = e.capabilities;
      if (!hasMembers(c, [], ["itar"])) return `${at}.capabilities`;
      if (Object.hasOwn(c, "itar") && typeof c.itar !== "boolean") return `${at}.capabilities.itar`;
    }
    const hasAlg = Object.hasOwn(e, "enc_alg");
    if (hasAlg !== Object.hasOwn(e, "enc_public_key")) return `${at}.enc_alg / enc_public_key`;
    if (hasAlg) {
      if (e.enc_alg !== DIRECTORY_KEM_ALG) return `${at}.enc_alg`;
      if (!isHexOf(e.enc_public_key, ML_KEM_1024_PUBLIC_KEY_BYTES)) return `${at}.enc_public_key`;
    }
  }
  return null;
}

/** Read directory JSON as it arrived — bytes (preferred) or text — or throw. The text
 *  is read strictly (size in UTF-8 bytes, no byte-order mark, no repeated member name)
 *  and the value is held to the exact shape above. This says nothing about trust:
 *  `verifyDirectory` checks the root's signature. */
export function parseDirectoryJson(input: string | Uint8Array): Directory {
  const value = parseStrictJson(input, { maxBytes: MAX_DIRECTORY_JSON_BYTES, label: "directory" });
  const why = directoryShapeError(value);
  if (why !== null) throw new Error(`malformed directory: ${why}`);
  return value as Directory;
}

/** Verify a directory: it has exactly the shape above, `at` falls within its own
 *  freshness window [issued_at, valid_until), and its signature verifies against the
 *  trust-root public key (hex). The window is part of the signed body, so it cannot
 *  be widened without breaking the root signature; enforcing it here additionally
 *  bounds how long a stale (but validly-signed) directory can be replayed — the
 *  in-band limit on revocation rollback. Fails closed on malformed input, and every
 *  other function in this module assumes it has been called and returned true. */
export function verifyDirectory(
  dir: Directory,
  rootPublicKeyHex: string,
  at: Date = new Date(),
): boolean {
  if (directoryShapeError(dir) !== null) return false;
  const t = at.getTime();
  // Strict, shared datetime parse (isoDateTimeMs === Rust rfc3339_millis) so the
  // two implementations agree on the freshness window byte for byte. A lenient
  // Date.parse would accept timestamps (trailing offset, date-only, RFC2822) the
  // Rust verifier refuses — and offset forms shift the instant — producing
  // opposite verify verdicts across implementations.
  const issued = isoDateTimeMs(dir.issued_at);
  const until = isoDateTimeMs(dir.valid_until);
  if (issued === null || until === null) return false;
  if (!(issued <= t && t < until)) return false;
  if (!dir.sig) return false;
  try {
    return verifyBody(
      SIG_DOMAIN.directory,
      directoryBody(dir),
      dir.sig,
      hexToBytes(rootPublicKeyHex),
    );
  } catch {
    return false;
  }
}

/** Usable at `t`: active, and inside [valid_from, valid_until). (The algorithm is
 *  fixed by the directory's shape, so it is not re-checked here.) */
function inWindow(e: DirectoryEntry, t: number): boolean {
  // Strict datetime parse, matching the Rust verifier (see verifyDirectory).
  const w = windowOf(e.valid_from, e.valid_until);
  return e.status === "active" && w !== null && w.from <= t && t < w.until;
}

/** The active, in-window entry with this key id. A kid appears on at most one entry of
 *  a verified directory, so there is nothing to choose between. */
export function entryByKid(dir: Directory, kid: string, at: Date = new Date()): DirectoryEntry | undefined {
  const t = at.getTime();
  return dir.entries.find((e) => e.kid === kid && inWindow(e, t));
}

/** The entry to ENCRYPT to for an org: among its active, in-window entries that carry
 *  an encryption key, the one whose validity started most recently (ties: the greater
 *  kid). An org legitimately has several in-window entries while it rotates keys, so
 *  the choice must not depend on the order the root happened to list them in — taking
 *  the first one sealed to the old key or the new key depending on directory order. */
export function encryptionEntryByOrg(
  dir: Directory,
  orgId: string,
  at: Date = new Date(),
): DirectoryEntry | undefined {
  const t = at.getTime();
  let best: DirectoryEntry | undefined;
  for (const e of dir.entries) {
    if (e.org_id !== orgId || !inWindow(e, t) || !e.enc_public_key) continue;
    if (
      !best ||
      isoDateTimeMs(e.valid_from)! > isoDateTimeMs(best.valid_from)! ||
      (isoDateTimeMs(e.valid_from) === isoDateTimeMs(best.valid_from) && e.kid > best.kid)
    ) {
      best = e;
    }
  }
  return best;
}

/** Whether an org is attested (by the directory) to hold a capability, e.g. ITAR.
 *  Scans EVERY active, in-window entry for the org — an org may legitimately have
 *  several entries (overlapping key rotation) — so the answer does not depend on
 *  entry ordering. This matches the Rust verifier's `.any()` (sign.rs
 *  `org_has_itar`); checking only the first entry (as an earlier version did) let
 *  the two implementations reach opposite export-control decisions. */
export function orgHasCapability(
  dir: Directory,
  orgId: string,
  cap: "itar",
  at: Date = new Date(),
): boolean {
  const t = at.getTime();
  return dir.entries.some(
    (e) => e.org_id === orgId && inWindow(e, t) && Boolean(e.capabilities?.[cap]),
  );
}
