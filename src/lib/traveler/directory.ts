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

export const DIRECTORY_SPEC = "sje-directory/0.1.0" as const;

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

/** Verify the directory's own signature against the trust-root public key (hex),
 *  and that `at` falls within the directory's own freshness window
 *  [issued_at, valid_until). The window is part of the signed body, so it cannot
 *  be widened without breaking the root signature; enforcing it here additionally
 *  bounds how long a stale (but validly-signed) directory can be replayed — the
 *  in-band limit on revocation rollback. Fails closed on malformed input. */
export function verifyDirectory(
  dir: Directory,
  rootPublicKeyHex: string,
  at: Date = new Date(),
): boolean {
  if (dir.spec !== DIRECTORY_SPEC || !dir.sig) return false;
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

function inWindow(e: DirectoryEntry, t: number): boolean {
  // Strict datetime parse, matching the Rust verifier (see verifyDirectory).
  const from = isoDateTimeMs(e.valid_from);
  const until = isoDateTimeMs(e.valid_until);
  return (
    e.status === "active" &&
    e.alg === SIG_ALG &&
    from !== null &&
    until !== null &&
    from <= t &&
    t < until
  );
}

/** The active, in-window entry with this key id. */
export function entryByKid(dir: Directory, kid: string, at: Date = new Date()): DirectoryEntry | undefined {
  const t = at.getTime();
  return dir.entries.find((e) => e.kid === kid && inWindow(e, t));
}

/** The active, in-window entry for an org. */
export function entryByOrg(dir: Directory, orgId: string, at: Date = new Date()): DirectoryEntry | undefined {
  const t = at.getTime();
  return dir.entries.find((e) => e.org_id === orgId && inWindow(e, t));
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
