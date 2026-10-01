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
 *  Two envelope specs are supported, and the choice is always REPORTED, never
 *  silent: when a verifying prekey bundle with a usable one-time prekey is supplied,
 *  `sealTraveler` uses the forward-secret envelope (`sje-envelope/0.2.0`) and returns
 *  `forwardSecret: true`; otherwise it falls back to the static envelope
 *  (`sje-envelope/0.1.0`) and returns `false`. `requireForwardSecret` turns the
 *  fallback into an error so a caller can refuse to send without forward secrecy.
 */
import { travelerToZip, importTravelerFile } from "./zip.ts";
import {
  sealEnvelope,
  openEnvelope,
  recipientByOrg,
  sealFsEnvelope,
  openFsEnvelope,
  fsRecipientFromBundle,
  ENVELOPE_SPEC,
  FS_ENVELOPE_SPEC,
  type Envelope,
  type FsEnvelope,
  type FsSealRecipient,
} from "./envelope.ts";
import { verifyDirectory, type Directory } from "./directory.ts";
import type { PrekeyBundle } from "./prekeys.ts";
import type { Keystore, Unlocked } from "./keystore.ts";
import type { Traveler } from "./types.ts";

/** The on-the-wire encrypted artifact — static (0.1) or forward-secret (0.2). */
export type SjeEnvelope = Envelope | FsEnvelope;

export type SealOptions = {
  directory: Directory;
  rootPublicKeyHex: string;
  recipientOrg: string;
  /** A signed prekey bundle (public). When it verifies and has a usable prekey, the
   *  forward-secret envelope is used; otherwise the static envelope (unless
   *  `requireForwardSecret`). */
  prekeyBundle?: PrekeyBundle;
  /** Throw instead of silently falling back to the static envelope. */
  requireForwardSecret?: boolean;
  /** Choose a specific prekey from the bundle (default: a random one). Mainly for
   *  tests and soak, which need collision-free, deterministic selection. */
  prekeyId?: string;
  at?: Date;
};

export type OpenOptions = {
  /** Persist the keystore blob returned after a one-time prekey is consumed. Called
   *  on the forward-secret path BEFORE the secret is used, so a crash cannot
   *  resurrect a consumed prekey. Omit it and forward secrecy holds only in-memory
   *  for the life of this process. */
  persistKeystore?: (keystore: Keystore) => void | Promise<void>;
};

/** Pick a prekey index from a CSPRNG. Modulo bias is irrelevant here — this only
 *  load-balances which one-time prekey a sender consumes, not key material. */
function randomIndex(n: number): number {
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("a secure random source (crypto.getRandomValues) is required");
  }
  return crypto.getRandomValues(new Uint32Array(1))[0]! % n;
}

/** Resolve a forward-secret recipient from the supplied bundle, or undefined if the
 *  bundle has no prekeys, the requested prekey is absent, or the bundle does not
 *  verify against the trust root for this org. */
function resolveFsRecipient(opts: SealOptions, when: Date): FsSealRecipient | undefined {
  const bundle = opts.prekeyBundle;
  if (!bundle) return undefined;
  const ids = (bundle.prekeys ?? []).map((p) => p.prekey_id);
  if (ids.length === 0) return undefined;
  let prekeyId: string;
  if (opts.prekeyId !== undefined) {
    if (!ids.includes(opts.prekeyId)) return undefined;
    prekeyId = opts.prekeyId;
  } else {
    prekeyId = ids[randomIndex(ids.length)]!;
  }
  // fsRecipientFromBundle re-verifies the directory + bundle signature and the org
  // match, so a tampered or wrong-org bundle resolves to nothing (fails closed).
  return fsRecipientFromBundle(opts.directory, bundle, opts.recipientOrg, prekeyId, opts.rootPublicKeyHex, when);
}

/** Encrypt a traveler to a directory-attested recipient. Verifies the directory
 *  against the trust root BEFORE resolving the recipient — `recipientByOrg` /
 *  `fsRecipientFromBundle` resolve attested keys, but skipping the directory check
 *  would still let a sealer trust an attacker-substituted directory. Returns the
 *  envelope and whether forward secrecy was used (always reported; never a silent
 *  downgrade). */
export async function sealTraveler(
  traveler: Traveler,
  opts: SealOptions,
): Promise<{ envelope: SjeEnvelope; forwardSecret: boolean }> {
  const when = opts.at ?? new Date();
  if (!verifyDirectory(opts.directory, opts.rootPublicKeyHex, when)) {
    throw new Error("sealTraveler: key directory does not verify against the trust root");
  }
  const zipBytes = new Uint8Array(await (await travelerToZip(traveler)).arrayBuffer());

  // Prefer forward secrecy when a verifying bundle with a usable prekey exists.
  const fsRecipient = resolveFsRecipient(opts, when);
  if (fsRecipient) {
    return { envelope: sealFsEnvelope(zipBytes, [fsRecipient]), forwardSecret: true };
  }
  if (opts.requireForwardSecret) {
    throw new Error(
      "sealTraveler: forward secrecy required but no verifying prekey bundle with a usable prekey is available",
    );
  }

  // Explicit, reported fallback to the static envelope.
  const recipient = recipientByOrg(opts.directory, opts.recipientOrg, when);
  if (!recipient) {
    throw new Error(`sealTraveler: no in-window ML-KEM recipient for ${opts.recipientOrg}`);
  }
  return { envelope: sealEnvelope(zipBytes, [recipient]), forwardSecret: false };
}

/** Decrypt an `.sje` envelope with an unlocked keystore and run the defensive
 *  import. Dispatches on the envelope spec: the static path uses the identity
 *  secret; the forward-secret path additionally consumes (deletes) the one-time
 *  prekey named by the recipient entry. Throws if the envelope does not address this
 *  keystore, if decryption fails (tamper / wrong key / spent prekey), or if the
 *  decrypted payload is not a valid archive. */
export async function openTraveler(
  envelope: SjeEnvelope,
  keystore: Unlocked,
  opts?: OpenOptions,
): Promise<Traveler> {
  // Captured before the branches below narrow `envelope` to `never`, so the final
  // throw can still name an unrecognized spec on a malformed runtime input.
  const spec = (envelope as Partial<SjeEnvelope> | null | undefined)?.spec;
  if (envelope?.spec === ENVELOPE_SPEC) {
    if (!envelope.recipients?.some((r) => r.kid === keystore.kid)) {
      throw new Error("openTraveler: envelope has no recipient entry for this keystore");
    }
    const zipBytes = openEnvelope(envelope, keystore.kid, keystore.staticSecretKey());
    return toTraveler(zipBytes);
  }

  if (envelope?.spec === FS_ENVELOPE_SPEC) {
    const r = envelope.recipients?.find((x) => x.kid === keystore.kid);
    if (!r) {
      throw new Error("openTraveler: envelope has no recipient entry for this keystore");
    }
    // Look up the one-time prekey secret WITHOUT consuming it, and verify+decrypt
    // FIRST. A prekey_id is public (it travels in the signed bundle), so consuming
    // before authentication would let anyone burn a victim's prekeys with a forged
    // envelope — an unauthenticated forward-secrecy DoS. A spent/unknown prekey →
    // refuse.
    const onetime = keystore.peekPrekey(r.prekey_id);
    if (!onetime) {
      throw new Error("openTraveler: one-time prekey already consumed or not held by this keystore");
    }
    const zipBytes = openFsEnvelope(envelope, keystore.kid, keystore.staticSecretKey(), onetime);
    // Authenticated: only now spend the one-time prekey, persisting the deletion
    // before the plaintext is released, so it can never open a second envelope.
    // (Accepted trade: a crash between a successful open and the persist resurrects
    // THIS one prekey — far less harmful than letting an attacker burn the pool.)
    const { keystore: updated } = keystore.consumePrekey(r.prekey_id);
    if (opts?.persistKeystore) await opts.persistKeystore(updated);
    return toTraveler(zipBytes);
  }

  throw new Error(`openTraveler: unsupported envelope spec ${String(spec)}`);
}

/** Copy the decrypted bytes into a fresh `Uint8Array<ArrayBuffer>` (openEnvelope
 *  returns `Uint8Array<ArrayBufferLike>`, which the File constructor rejects under
 *  TS strict) and run the existing hardened zip import. */
function toTraveler(zipBytes: Uint8Array): Promise<Traveler> {
  return importTravelerFile(
    new File([new Uint8Array(zipBytes)], "received.sje.zip", { type: "application/zip" }),
  );
}

/** Parse untrusted bytes/JSON into a recognized envelope, or throw. Only shape and
 *  spec are checked here; cryptographic verification happens in `openTraveler`. */
export function parseSjeEnvelope(input: unknown): SjeEnvelope {
  const obj = typeof input === "string" ? (JSON.parse(input) as unknown) : input;
  const e = obj as Partial<Envelope | FsEnvelope>;
  // Validate the fields openTraveler relies on, not just the spec — a "recognized"
  // envelope must have a string payload + payload_nonce and a non-empty recipient
  // list whose entries each carry a string kid (the rest of each recipient's hex
  // fields are validated cryptographically downstream, which fails closed).
  const recipientsOk =
    Array.isArray(e?.recipients) &&
    e.recipients.length > 0 &&
    e.recipients.every((r) => r && typeof r === "object" && typeof (r as { kid?: unknown }).kid === "string");
  if (
    !e ||
    typeof e !== "object" ||
    (e.spec !== ENVELOPE_SPEC && e.spec !== FS_ENVELOPE_SPEC) ||
    typeof e.payload !== "string" ||
    typeof (e as Envelope).payload_nonce !== "string" ||
    !recipientsOk
  ) {
    throw new Error("not a recognized SJE envelope");
  }
  return e as SjeEnvelope;
}
