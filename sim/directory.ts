/** A seeded, signed key directory + one-time prekey bundle for the soak's
 *  authenticity / confidentiality phase. Built once per run from the Rng so the
 *  ML-DSA and ML-KEM keys are deterministic. Mirrors the shape the conformance
 *  generator produces, but freshly keyed so the soak exercises real sign/verify
 *  and seal/open rather than replaying a fixed vector.
 */
import { Rng } from "./rng.ts";
import { keypairFromSeed, type Keypair } from "../src/lib/traveler/signature.ts";
import { kemKeypairFromSeed } from "../src/lib/traveler/envelope.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { PREKEY_BUNDLE_SPEC, signPrekeyBundle, type PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";

type Kem = { publicKey: Uint8Array; secretKey: Uint8Array };

export type OrgKeys = { orgId: string; kid: string; signer: Keypair; kem: Kem; itar: boolean };

export type Trust = {
  rootPublicKeyHex: string;
  directory: Directory;
  orgs: Map<string, OrgKeys>;
  /** A prekey bundle published by `prekeyOrg` (a recipient of forward-secret envelopes). */
  prekeyOrg: string;
  prekeyBundle: PrekeyBundle;
  prekeySecret: (prekeyId: string) => Uint8Array | undefined;
};

const ORGS: Array<{ orgId: string; itar: boolean }> = [
  { orgId: "org_northline", itar: false }, // buyer
  { orgId: "org_huron", itar: true },
  { orgId: "org_summitfab", itar: false },
  { orgId: "org_redriver", itar: false },
];

const ISSUED = "2026-01-01T00:00:00.000Z";
const UNTIL = "2030-01-01T00:00:00.000Z";

export function buildTrust(rng: Rng): Trust {
  const root = keypairFromSeed(rng.bytes(32));
  const orgs = new Map<string, OrgKeys>();
  const entries: Directory["entries"] = [];
  for (const { orgId, itar } of ORGS) {
    const signer = keypairFromSeed(rng.bytes(32));
    const kem = kemKeypairFromSeed(rng.bytes(64));
    const kid = `${orgId}-2026`;
    orgs.set(orgId, { orgId, kid, signer, kem, itar });
    entries.push({
      org_id: orgId,
      kid,
      alg: "ML-DSA-87",
      public_key: bytesToHex(signer.publicKey),
      valid_from: ISSUED,
      valid_until: UNTIL,
      status: "active",
      capabilities: { itar },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(kem.publicKey),
    });
  }
  const directory: Directory = {
    spec: DIRECTORY_SPEC,
    issued_at: ISSUED,
    valid_until: UNTIL,
    root_kid: "root-2026",
    entries,
  };
  directory.sig = signDirectory(directory, root.secretKey);

  // A seller org publishes one-time prekeys so a buyer can seal forward-secret
  // envelopes to it. The bundle is signed by that org's identity key.
  const prekeyOrg = "org_huron";
  const rk = orgs.get(prekeyOrg)!;
  const preKps = [kemKeypairFromSeed(rng.bytes(64)), kemKeypairFromSeed(rng.bytes(64))];
  const bundle: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: prekeyOrg,
    kid: rk.kid,
    enc_alg: "ML-KEM-1024",
    issued_at: ISSUED,
    valid_until: UNTIL,
    prekeys: preKps.map((kp, i) => ({
      prekey_id: `${prekeyOrg}-ot-${i + 1}`,
      public_key: bytesToHex(kp.publicKey),
    })),
  };
  bundle.sig = signPrekeyBundle(bundle, rk.signer.secretKey);
  const secretByPrekey = new Map(preKps.map((kp, i) => [`${prekeyOrg}-ot-${i + 1}`, kp.secretKey]));

  return {
    rootPublicKeyHex: bytesToHex(root.publicKey),
    directory,
    orgs,
    prekeyOrg,
    prekeyBundle: bundle,
    prekeySecret: (id) => secretByPrekey.get(id),
  };
}
