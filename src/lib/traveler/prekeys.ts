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
import { isoDateTimeMs } from "./datetime.ts";
import { SIG_DOMAIN, signBody, verifyBody } from "./signature.ts";
import { hexToBytes } from "./bytes.ts";
import { parseStrictJson } from "./wire.ts";
import {
  KEY_ID_RE,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ORG_ID_RE,
  entryByKid,
  hasMembers,
  isHexOf,
  verifyDirectory,
  windowOf,
  type Directory,
} from "./directory.ts";

export const PREKEY_BUNDLE_SPEC = "sje-prekeys/0.1.0" as const;
/** Most one-time prekeys one bundle may carry. */
export const MAX_BUNDLE_PREKEYS = 256;
/** A bundle's JSON text, in UTF-8 bytes (a prekey is ~3.2 KB). */
export const MAX_PREKEY_BUNDLE_JSON_BYTES = 1024 * 1024;
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

/** Why `bundle` is not a well-formed signed prekey bundle, or null if it is. Exact, and
 *  identical in the Rust core (`sign.rs` `prekey_bundle_shape`), for the same reason as
 *  the directory's shape (directory.ts): a signature says who signed the bytes, not
 *  that every reader takes the same meaning from them.
 *
 *    bundle  exactly { spec, org_id, kid, enc_alg, issued_at, valid_until, prekeys, sig }
 *    prekey  exactly { prekey_id, public_key }: an id of 1–64 [A-Za-z0-9._-] (it is
 *            concatenated into an envelope's key-derivation label) and a 1568-byte
 *            ML-KEM-1024 key; no id twice; at most 256 */
export function prekeyBundleShapeError(bundle: unknown): string | null {
  if (
    !hasMembers(bundle, [
      "spec",
      "org_id",
      "kid",
      "enc_alg",
      "issued_at",
      "valid_until",
      "prekeys",
      "sig",
    ])
  ) {
    return "unexpected or missing members";
  }
  if (bundle.spec !== PREKEY_BUNDLE_SPEC) return "unsupported spec";
  if (typeof bundle.org_id !== "string" || !ORG_ID_RE.test(bundle.org_id)) return "org_id";
  if (typeof bundle.kid !== "string" || !KEY_ID_RE.test(bundle.kid)) return "kid";
  if (bundle.enc_alg !== PREKEY_KEM_ALG) return "enc_alg";
  if (!windowOf(bundle.issued_at, bundle.valid_until)) return "issued_at / valid_until";
  if (!isHexOf(bundle.sig, ML_DSA_87_SIGNATURE_BYTES)) return "sig";
  const prekeys = bundle.prekeys;
  if (!Array.isArray(prekeys) || prekeys.length > MAX_BUNDLE_PREKEYS) return "prekeys";
  const ids = new Set<string>();
  for (const [i, p] of prekeys.entries()) {
    const at = `prekeys[${i}]`;
    if (!hasMembers(p, ["prekey_id", "public_key"])) return `${at} has unexpected or missing members`;
    if (typeof p.prekey_id !== "string" || !KEY_ID_RE.test(p.prekey_id)) return `${at}.prekey_id`;
    if (ids.has(p.prekey_id)) return `${at}.prekey_id repeats an earlier prekey`;
    ids.add(p.prekey_id);
    if (!isHexOf(p.public_key, ML_KEM_1024_PUBLIC_KEY_BYTES)) return `${at}.public_key`;
  }
  return null;
}

/** Read prekey-bundle JSON as it arrived — bytes (preferred) or text — or throw:
 *  strictly read text, exact shape. Trust is `verifyPrekeyBundle`'s business. */
export function parsePrekeyBundleJson(input: string | Uint8Array): PrekeyBundle {
  const value = parseStrictJson(input, {
    maxBytes: MAX_PREKEY_BUNDLE_JSON_BYTES,
    label: "prekey bundle",
  });
  const why = prekeyBundleShapeError(value);
  if (why !== null) throw new Error(`malformed prekey bundle: ${why}`);
  return value as PrekeyBundle;
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
  if (prekeyBundleShapeError(bundle) !== null || !bundle.sig) return undefined;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) return undefined;
  const t = when.getTime();
  // Strict, shared datetime parse (matches Rust rfc3339_millis / verifyDirectory)
  // so both implementations agree on the bundle's validity window.
  const issued = isoDateTimeMs(bundle.issued_at);
  const until = isoDateTimeMs(bundle.valid_until);
  if (issued === null || until === null) return undefined;
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
