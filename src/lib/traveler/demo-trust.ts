import { keypairFromSeed } from "./signature.ts";
import { kemKeypairFromSeed } from "./envelope.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory, type DirectoryEntry } from "./directory.ts";
import { bytesToHex } from "./bytes.ts";
import { rootDigest } from "./fingerprint.ts";

/** A deterministic demo trust anchor, so the "Seal & send" flow is completable without
 *  hand-building and signing a directory. The recipients are sample shops with real
 *  ML-KEM-1024 encryption keys, so sealing to one produces genuine ciphertext.
 *
 *  IT PROVES NOTHING AND PROTECTS NOTHING. Every secret behind it is a constant in this
 *  file — the root's signing seed, each org's signing seed, each org's decryption seed —
 *  and this file is public. So anyone can:
 *    - sign a directory this root "verifies",
 *    - sign a traveler, quote or award as any demo org, and have it verify, and
 *    - decrypt anything sealed to a demo org.
 *  The directory still passes the same signature + window verification every other
 *  directory does (`verifyDirectory` knows nothing about demos, and must not: it
 *  answers "did this root sign these bytes"). What makes it a demo is WHO HOLDS THE
 *  SECRETS, and that is a fact about the root key — so the anchor is recognized by its
 *  root public key (`isDemoTrustRoot`), never by a flag stored next to it, which could
 *  be missing or forged. Every caller that shows a verdict or seals under a root —
 *  the desk, the MCP server, a script — should ask. */
const WINDOW = { issued_at: "2026-01-01T00:00:00.000Z", valid_until: "2032-01-01T00:00:00.000Z" };
const seed32 = (n: number) => new Uint8Array(32).fill(n);
const seed64 = (n: number) => new Uint8Array(64).fill(n);

const DEMO_ROOT_SEED_BYTE = 1;
const DEMO_ORGS = [
  { org_id: "org_summitfab", kid: "summit-demo", signByte: 10, encByte: 11 },
  { org_id: "org_redriver", kid: "redriver-demo", signByte: 12, encByte: 13 },
  { org_id: "org_cascade", kid: "cascade-demo", signByte: 14, encByte: 15 },
];

/** SHA-384 of the demo root's raw public-key bytes (`rootDigest` of it). A constant, so
 *  recognizing the demo anchor costs one hash and no key generation; demo-trust.test.ts
 *  pins it to the key the seed above actually derives. */
export const DEMO_ROOT_DIGEST =
  "dcb52a192c62706232ae544428fe141f119a9b31cb251bf504440c66c36cf2489f29118ff8dc28e5bb0d346af1f1426d";

/** What a person must be told wherever the demo anchor is in use, in plain words. */
export const DEMO_TRUST_WARNING =
  "DEMO trust anchor. Its root, signing and decryption keys are public: they are printed in " +
  "this project's source code. A signature that verifies under it proves nothing — anyone can " +
  "produce one — and anything sealed to its recipients can be read by anyone.";

/** True iff `rootPublicKeyHex` is the demo root — the key whose secret is public.
 *
 *  Decided from the key's bytes (so re-casing the hex changes nothing), not from any
 *  label, flag or `root_kid` that travels or is stored with it. False for anything
 *  that is not a key. */
export function isDemoTrustRoot(rootPublicKeyHex: unknown): boolean {
  return rootDigest(rootPublicKeyHex) === DEMO_ROOT_DIGEST;
}

export function buildDemoTrust(): {
  rootPublicKeyHex: string;
  directory: Directory;
  bundles: Record<string, never>;
} {
  const root = keypairFromSeed(seed32(DEMO_ROOT_SEED_BYTE));
  const entries: DirectoryEntry[] = DEMO_ORGS.map((o) => ({
    org_id: o.org_id,
    kid: o.kid,
    alg: "ML-DSA-87",
    public_key: bytesToHex(keypairFromSeed(seed32(o.signByte)).publicKey),
    valid_from: WINDOW.issued_at,
    valid_until: WINDOW.valid_until,
    status: "active",
    enc_alg: "ML-KEM-1024",
    enc_public_key: bytesToHex(kemKeypairFromSeed(seed64(o.encByte)).publicKey),
  }));
  const body: Directory = { spec: DIRECTORY_SPEC, ...WINDOW, root_kid: "root-demo", entries };
  return {
    rootPublicKeyHex: bytesToHex(root.publicKey),
    directory: { ...body, sig: signDirectory(body, root.secretKey) },
    bundles: {},
  };
}
