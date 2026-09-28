/** Single-use prekey bundles — the forward-secrecy companion to the directory.
 *
 *  Static-key encryption (envelope.ts, sje-envelope/0.1.0) has no forward secrecy:
 *  one later compromise of a recipient's long-lived ML-KEM key exposes every
 *  stored envelope sent to it. A prekey bundle fixes that: a recipient org
 *  publishes a batch of *one-time* ML-KEM-1024 encryption prekeys, the whole
 *  bundle signed by the org's ML-DSA identity key. A sender verifies the bundle
 *  against the signed directory (so a prekey is provably the org's, not an
 *  attacker's), encapsulates to one prekey (see envelope.ts sealFsEnvelope), and
 *  the recipient deletes that prekey's secret after opening. Once the one-time
 *  secret is gone, a later compromise of the static key cannot recover the
 *  message — forward secrecy.
 *
 *  SJE stays a file format: bundles are distributed out of band, like the
 *  directory. Signing lives here for the CLI / server / test-vector path; the
 *  browser desk verifies only and never holds signing keys.
 */
import { canonicalJson } from "./canonical.ts";
import { SIG_DOMAIN, signBody, verifyBody } from "./signature.ts";
import { hexToBytes } from "./bytes.ts";
import { entryByKid, verifyDirectory, type Directory } from "./directory.ts";

export const PREKEY_BUNDLE_SPEC = "sje-prekeys/0.1.0" as const;
/** The prekey algorithm, matching envelope.ts KEM_ALG. Kept as a literal here to
 *  avoid an import cycle with the confidentiality module. */
const PREKEY_KEM_ALG = "ML-KEM-1024" as const;

export type Prekey = { prekey_id: string; public_key: string }; // hex ML-KEM-1024 ek
export type PrekeyBundle = {
  spec: typeof PREKEY_BUNDLE_SPEC;
  org_id: string;
  kid: string; // the ML-DSA signing kid; must resolve in the directory to org_id
  enc_alg: string; // "ML-KEM-1024"
  issued_at: string;
  valid_until: string;
  prekeys: Prekey[];
  sig?: string; // hex ML-DSA signature by kid over the canonical body (minus sig)
};

/** The canonical bytes the org signs: the bundle without its own signature. */
export function prekeyBundleBody(b: PrekeyBundle): string {
  const { sig: _omit, ...rest } = b;
  void _omit;
  return canonicalJson(rest);
}

export function signPrekeyBundle(b: PrekeyBundle, secretKey: Uint8Array): string {
  return signBody(SIG_DOMAIN.prekeys, prekeyBundleBody(b), secretKey);
}

/** Verify a prekey bundle: the directory verifies against the trust root, the
 *  bundle's signing kid resolves (active, in-window) to an entry whose org equals
 *  the bundle's org_id, the bundle's own [issued_at, valid_until) covers `at`, and
 *  the ML-DSA signature over the canonical body checks out. Returns the verified
 *  bundle (so callers seal only to vetted prekeys) or undefined; fails closed. */
export function verifyPrekeyBundle(
  bundle: PrekeyBundle,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): PrekeyBundle | undefined {
  if (bundle.spec !== PREKEY_BUNDLE_SPEC || !bundle.sig) return undefined;
  if (bundle.enc_alg !== PREKEY_KEM_ALG) return undefined;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) return undefined;
  const t = when.getTime();
  const issued = Date.parse(bundle.issued_at);
  const until = Date.parse(bundle.valid_until);
  if (!Number.isFinite(issued) || !Number.isFinite(until)) return undefined;
  if (!(issued <= t && t < until)) return undefined;
  const entry = entryByKid(dir, bundle.kid, when);
  if (!entry || entry.org_id !== bundle.org_id) return undefined;
  let ok = false;
  try {
    ok = verifyBody(SIG_DOMAIN.prekeys, prekeyBundleBody(bundle), bundle.sig, hexToBytes(entry.public_key));
  } catch {
    ok = false; // malformed key material fails closed
  }
  return ok ? bundle : undefined;
}

/** Find a prekey in a bundle by id. */
export function prekeyById(bundle: PrekeyBundle, prekeyId: string): Prekey | undefined {
  return bundle.prekeys.find((p) => p.prekey_id === prekeyId);
}
