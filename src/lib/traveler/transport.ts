/** Encrypted transport — the layer that makes what's SENT ciphertext.
 *
 *  `sealTraveler` turns a traveler into an encrypted `.sje` envelope addressed to a
 *  recipient resolved through the signed directory; `openTraveler` decrypts it with
 *  an unlocked keystore and runs the existing defensive import. The envelope payload
 *  is exactly the bytes of `travelerToZip`, so opening reuses the whole hardened
 *  zip-import path unchanged — decryption just removes the confidentiality wrapper.
 *
 *  Sealing needs only public keys (the recipient's, from the directory), so it can
 *  run anywhere — including the browser — with no secret. Opening needs the
 *  recipient's ML-KEM secret, supplied by an unlocked keystore (keystore.ts).
 *
 *  Static path here (`sje-envelope/0.1.0`); the forward-secret path
 *  (`sje-envelope/0.2.0`, one-time prekeys) is layered on in a later step.
 */
import { travelerToZip, importTravelerFile } from "./zip.ts";
import {
  sealEnvelope,
  openEnvelope,
  recipientByOrg,
  ENVELOPE_SPEC,
  type Envelope,
} from "./envelope.ts";
import { verifyDirectory, type Directory } from "./directory.ts";
import type { Unlocked } from "./keystore.ts";
import type { Traveler } from "./types.ts";

/** The on-the-wire encrypted artifact. (Union widens to the forward-secret
 *  envelope when that path lands.) */
export type SjeEnvelope = Envelope;

export type SealOptions = {
  directory: Directory;
  rootPublicKeyHex: string;
  recipientOrg: string;
  at?: Date;
};

/** Encrypt a traveler to a directory-attested recipient. Verifies the directory
 *  against the trust root BEFORE resolving the recipient — `recipientByOrg` does
 *  not verify, so skipping this would let a sealer encrypt to an attacker-
 *  substituted key. Returns the envelope and whether forward secrecy was used
 *  (always false on the static path; never a silent claim). */
export async function sealTraveler(
  traveler: Traveler,
  opts: SealOptions,
): Promise<{ envelope: SjeEnvelope; forwardSecret: boolean }> {
  const when = opts.at ?? new Date();
  if (!verifyDirectory(opts.directory, opts.rootPublicKeyHex, when)) {
    throw new Error("sealTraveler: key directory does not verify against the trust root");
  }
  const recipient = recipientByOrg(opts.directory, opts.recipientOrg, when);
  if (!recipient) {
    throw new Error(`sealTraveler: no in-window ML-KEM recipient for ${opts.recipientOrg}`);
  }
  const zipBytes = new Uint8Array(await (await travelerToZip(traveler)).arrayBuffer());
  return { envelope: sealEnvelope(zipBytes, [recipient]), forwardSecret: false };
}

/** Decrypt an `.sje` envelope with an unlocked keystore and run the defensive
 *  import. Throws if the envelope does not address this keystore, if decryption
 *  fails (tamper / wrong key), or if the decrypted payload is not a valid archive. */
export async function openTraveler(envelope: SjeEnvelope, keystore: Unlocked): Promise<Traveler> {
  if (envelope?.spec === ENVELOPE_SPEC) {
    if (!envelope.recipients?.some((r) => r.kid === keystore.kid)) {
      throw new Error("openTraveler: envelope has no recipient entry for this keystore");
    }
    const zipBytes = openEnvelope(envelope, keystore.kid, keystore.staticSecretKey());
    // Copy into a fresh Uint8Array<ArrayBuffer> so the File constructor accepts it
    // (openEnvelope returns Uint8Array<ArrayBufferLike>).
    return importTravelerFile(new File([new Uint8Array(zipBytes)], "received.sje.zip", { type: "application/zip" }));
  }
  throw new Error(`openTraveler: unsupported envelope spec ${String(envelope?.spec)}`);
}

/** Parse untrusted bytes/JSON into a recognized envelope, or throw. Only shape and
 *  spec are checked here; cryptographic verification happens in `openTraveler`. */
export function parseSjeEnvelope(input: unknown): SjeEnvelope {
  const obj = typeof input === "string" ? (JSON.parse(input) as unknown) : input;
  const e = obj as Partial<Envelope>;
  if (!e || typeof e !== "object" || e.spec !== ENVELOPE_SPEC || !Array.isArray(e.recipients) || typeof e.payload !== "string") {
    throw new Error("not a recognized SJE envelope");
  }
  return e as SjeEnvelope;
}
