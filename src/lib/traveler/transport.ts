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
import { randomBytes } from "./bytes.ts";
import { travelerToZip, importTravelerFile } from "./zip.ts";
import {
  assertEnvelopeShape,
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
import { MAX_ENVELOPE_JSON_BYTES, type Traveler } from "./types.ts";
import { parseStrictJson } from "./wire.ts";

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
  /** Persist the keystore blob returned when a one-time prekey is spent (see
   *  `OpenedTraveler.commit`). Omit it and the deletion holds only in memory, for the
   *  life of this process. If it throws, the commit throws: the caller must not report
   *  the prekey as deleted. */
  persistKeystore?: (keystore: Keystore) => void | Promise<void>;
};

/** Pick a prekey index from a CSPRNG. Modulo bias is irrelevant here — this only
 *  load-balances which one-time prekey a sender consumes, not key material. */
function randomIndex(n: number): number {
  return new DataView(randomBytes(4).buffer).getUint32(0) % n;
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

/** A decrypted traveler whose one-time prekey has not been spent yet. */
export type OpenedTraveler = {
  traveler: Traveler;
  /** Whether the envelope was forward-secret (a one-time prekey is involved). */
  forwardSecret: boolean;
  /** Spend the one-time prekey this envelope used, and persist that. Call it once the
   *  traveler has been ADMITTED (or when the envelope is being discarded for good).
   *  Idempotent; a no-op for a static envelope. */
  commit: () => Promise<void>;
};

/** Decrypt an `.sje` envelope and parse the traveler inside it, WITHOUT yet spending
 *  the one-time prekey a forward-secret envelope used.
 *
 *  Decrypting is not the same as accepting. Between the two sit the archive checks, the
 *  receive policy (import-policy.ts) and, sometimes, a person deciding whether to trust
 *  an unverified award. If the prekey were spent the moment the envelope decrypted, a
 *  refusal at any of those steps — or a closed tab — would leave an envelope that can
 *  never be opened again, and a junk payload under a valid tag would burn a prekey for
 *  nothing. So spending is the caller's explicit second step: `commit()`.
 *
 *  What that means for forward secrecy, stated plainly: the one-time secret is deleted
 *  when the traveler is admitted, not when it is decrypted. Until `commit()` runs the
 *  same envelope can be opened again — by its recipient, and by anyone who later
 *  obtains the recipient's keystore AND its passphrase.
 *
 *  Throws if the envelope is malformed, does not address this keystore, fails to
 *  decrypt (tamper / wrong key / a prekey already spent), or does not carry a valid
 *  archive. Nothing is spent on a throw. */
export async function openTravelerDeferred(
  envelope: SjeEnvelope,
  keystore: Unlocked,
  opts?: OpenOptions,
): Promise<OpenedTraveler> {
  // Shape first, whatever the caller's types claim: nothing below (the recipient
  // lookup, the prekey lookup) should run on a value that is not exactly an envelope.
  assertEnvelopeShape(envelope);
  if (envelope.spec === ENVELOPE_SPEC) {
    if (!envelope.recipients.some((r) => r.kid === keystore.kid)) {
      throw new Error("openTraveler: envelope has no recipient entry for this keystore");
    }
    const zipBytes = openEnvelope(envelope, keystore.kid, keystore.staticSecretKey());
    return { traveler: await toTraveler(zipBytes), forwardSecret: false, commit: async () => {} };
  }

  if (envelope.spec === FS_ENVELOPE_SPEC) {
    const r = envelope.recipients.find((x) => x.kid === keystore.kid);
    if (!r) {
      throw new Error("openTraveler: envelope has no recipient entry for this keystore");
    }
    // Honest limit: prekey_id and the prekey public key are public (they travel in the
    // signed bundle), so a party holding the bundle CAN seal a validly-encrypted envelope
    // to any prekey — one-time prekey pools are exhaustible by anyone who can encrypt to
    // them, once the recipient admits what was sent. A spent/unknown prekey → refuse.
    const onetime = keystore.peekPrekey(r.prekey_id);
    if (!onetime) {
      throw new Error("openTraveler: one-time prekey already consumed or not held by this keystore");
    }
    const zipBytes = openFsEnvelope(envelope, keystore.kid, keystore.staticSecretKey(), onetime);
    const traveler = await toTraveler(zipBytes);
    let spent = false;
    const commit = async (): Promise<void> => {
      if (spent) return;
      spent = true;
      // Already gone (another open of the same envelope committed first): nothing to do.
      if (!keystore.peekPrekey(r.prekey_id)) return;
      const { keystore: updated } = keystore.consumePrekey(r.prekey_id);
      if (opts?.persistKeystore) await opts.persistKeystore(updated);
    };
    return { traveler, forwardSecret: true, commit };
  }

  throw new Error("openTraveler: unsupported envelope spec");
}

/** Decrypt an `.sje` envelope, spend its one-time prekey, and return the traveler — for
 *  a caller that accepts whatever a valid envelope carries. A caller that decides
 *  afterwards (a receive policy, a confirmation) uses `openTravelerDeferred` and commits
 *  only once the traveler is admitted. */
export async function openTraveler(
  envelope: SjeEnvelope,
  keystore: Unlocked,
  opts?: OpenOptions,
): Promise<Traveler> {
  const opened = await openTravelerDeferred(envelope, keystore, opts);
  await opened.commit();
  return opened.traveler;
}

/** Copy the decrypted bytes into a fresh `Uint8Array<ArrayBuffer>` (openEnvelope
 *  returns `Uint8Array<ArrayBufferLike>`, which the File constructor rejects under
 *  TS strict) and run the existing hardened zip import. */
function toTraveler(zipBytes: Uint8Array): Promise<Traveler> {
  return importTravelerFile(
    new File([new Uint8Array(zipBytes)], "received.sje.zip", { type: "application/zip" }),
  );
}

/** Parse an untrusted envelope — the `.sje` file's bytes (preferred), its text, or an
 *  already-parsed value — into a well-formed envelope, or throw.
 *
 *  Text and bytes go through the strict text boundary (wire.ts): size in UTF-8 bytes,
 *  no byte-order mark, no repeated member name. Every form is then held to the exact
 *  wire shape (`assertEnvelopeShape`). Nothing here uses a key; cryptographic
 *  verification is `openTraveler`. */
export function parseSjeEnvelope(input: unknown): SjeEnvelope {
  const value =
    typeof input === "string" || input instanceof Uint8Array
      ? parseStrictJson(input, { maxBytes: MAX_ENVELOPE_JSON_BYTES, label: "envelope" })
      : input;
  assertEnvelopeShape(value);
  return value;
}
