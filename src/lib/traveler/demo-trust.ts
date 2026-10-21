import { keypairFromSeed } from "./signature.ts";
import { kemKeypairFromSeed } from "./envelope.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory, type DirectoryEntry } from "./directory.ts";
import { bytesToHex } from "./bytes.ts";

/** A deterministic demo trust anchor, so the "Seal & send" flow is completable without
 *  hand-building and signing a directory. The recipients are sample shops with real
 *  ML-KEM-1024 encryption keys, so sealing to one produces genuine ciphertext.
 *
 *  This is a convenience for trying the demo, NOT a real trust root: a production desk
 *  loads a directory whose root public key it has verified out of band. The directory
 *  here still passes the same signature + window verification `setTrust` runs. */
const WINDOW = { issued_at: "2026-01-01T00:00:00.000Z", valid_until: "2032-01-01T00:00:00.000Z" };
const seed32 = (n: number) => new Uint8Array(32).fill(n);
const seed64 = (n: number) => new Uint8Array(64).fill(n);

const DEMO_ORGS = [
  { org_id: "org_summitfab", kid: "summit-demo", signByte: 10, encByte: 11 },
  { org_id: "org_redriver", kid: "redriver-demo", signByte: 12, encByte: 13 },
  { org_id: "org_cascade", kid: "cascade-demo", signByte: 14, encByte: 15 },
];

export function buildDemoTrust(): {
  rootPublicKeyHex: string;
  directory: Directory;
  bundles: Record<string, never>;
} {
  const root = keypairFromSeed(seed32(1));
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
