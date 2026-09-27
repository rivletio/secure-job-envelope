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
import { SIG_DOMAIN, SIG_ALG, signBody, verifyBody } from "./signature.ts";
import { hexToBytes } from "./bytes.ts";

export const DIRECTORY_SPEC = "sje-directory/0.1.0" as const;

export type DirectoryEntry = {
  org_id: string;
  kid: string;
  alg: string;
  public_key: string; // lowercase hex ML-DSA-87 public key
  valid_from: string;
  valid_until: string;
  status: "active" | "revoked";
  capabilities?: { itar?: boolean };
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

/** Verify the directory's own signature against the trust-root public key (hex). */
export function verifyDirectory(dir: Directory, rootPublicKeyHex: string): boolean {
  if (dir.spec !== DIRECTORY_SPEC || !dir.sig) return false;
  return verifyBody(SIG_DOMAIN.directory, directoryBody(dir), dir.sig, hexToBytes(rootPublicKeyHex));
}

function inWindow(e: DirectoryEntry, t: number): boolean {
  return (
    e.status === "active" &&
    e.alg === SIG_ALG &&
    Date.parse(e.valid_from) <= t &&
    t < Date.parse(e.valid_until)
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

/** Whether an org is attested (by the directory) to hold a capability, e.g. ITAR. */
export function orgHasCapability(
  dir: Directory,
  orgId: string,
  cap: "itar",
  at?: Date,
): boolean {
  return Boolean(entryByOrg(dir, orgId, at)?.capabilities?.[cap]);
}
