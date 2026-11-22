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
 *
 *  A forward-secret seal spends one of the recipient's one-time prekeys. The seal
 *  reports which (`prekeyId`), and the SENDER keeps the list and passes it back
 *  (`excludePrekeyIds`) so it never seals twice to one prekey — the second envelope
 *  could not be opened. See `sealTraveler` for what that does and does not cover.
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
import { prekeyBundleShapeError, verifyPrekeyBundle, type PrekeyBundle } from "./prekeys.ts";
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
  /** Choose a specific prekey from the bundle (default: a random unused one). Mainly
   *  for tests and soak, which need collision-free, deterministic selection. */
  prekeyId?: string;
  /** One-time prekeys of this bundle the sender has ALREADY sealed to — the
   *  `prekeyId`s earlier calls returned. They are never chosen again. When every prekey
   *  in the bundle is excluded there is no usable prekey: the seal falls back to the
   *  static envelope (reported: `forwardSecret: false`, `staticReason:
   *  "prekeys-exhausted"`) or throws under `requireForwardSecret`.
   *
   *  A sender MUST keep this list. A one-time prekey opens exactly one envelope: the
   *  recipient deletes it after the first, so a second envelope sealed to it can never
   *  be opened. `sealTraveler` has no memory between calls — without the list it picks
   *  at random from the same static bundle every time, and one honest sender sealing 20
   *  travelers to an 8-prekey bundle loses most of them while each seal reports
   *  `forwardSecret: true`. */
  excludePrekeyIds?: readonly string[];
  at?: Date;
};

/** Why a seal used the static envelope instead of the forward-secret one. */
export type StaticReason =
  /** No prekey bundle was supplied for the recipient. */
  | "no-bundle"
  /** A bundle was supplied but cannot be used: malformed, outside its validity window,
   *  not signed by the recipient org's directory key, or for another org. */
  | "bundle-not-verified"
  /** The bundle verifies, but every one-time prekey in it is in `excludePrekeyIds`
   *  (or it lists none): this sender has used them all. The recipient has to publish a
   *  fresh bundle. */
  | "prekeys-exhausted"
  /** The specific `prekeyId` asked for is not in the bundle, or is excluded. */
  | "prekey-unavailable";

export type SealResult = {
  envelope: SjeEnvelope;
  /** Whether the forward-secret envelope was used. Always reported; never a silent
   *  downgrade. */
  forwardSecret: boolean;
  /** The one-time prekey this envelope was sealed to (forward-secret only). The sender
   *  must remember it and pass it in `excludePrekeyIds` from now on. */
  prekeyId?: string;
  /** Present iff `forwardSecret` is false: why. */
  staticReason?: StaticReason;
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

/** Resolve a forward-secret recipient from the supplied bundle — or the reason there
 *  is none: no bundle, a bundle that does not verify against the trust root for this
 *  org, no prekey the sender has not already used, or a requested prekey that is absent
 *  or excluded. */
function resolveFsRecipient(opts: SealOptions, when: Date): FsSealRecipient | StaticReason {
  const bundle = opts.prekeyBundle;
  if (!bundle) return "no-bundle";
  // Shape first: the bundle is whatever the caller was handed, and nothing below should
  // read a `prekeys` that is not the array of { prekey_id, public_key } it claims to be.
  if (prekeyBundleShapeError(bundle) !== null) return "bundle-not-verified";
  const excluded = new Set(opts.excludePrekeyIds ?? []);
  const unused = bundle.prekeys.map((p) => p.prekey_id).filter((id) => !excluded.has(id));
  const wanted = opts.prekeyId;
  const pool = wanted === undefined ? unused : unused.filter((id) => id === wanted);
  if (pool.length === 0) {
    // Nothing to seal to. "Exhausted" is a statement about a bundle that verifies, so
    // say that only if it does.
    const vetted = verifyPrekeyBundle(bundle, opts.directory, opts.rootPublicKeyHex, when);
    if (!vetted || vetted.org_id !== opts.recipientOrg) return "bundle-not-verified";
    return unused.length === 0 ? "prekeys-exhausted" : "prekey-unavailable";
  }
  // Among the prekeys this sender has not used, pick at random. Random, not "the
  // first": a second sender holding the same public bundle is choosing too, and both
  // taking the first would collide every time. They can still collide — see
  // sealTraveler.
  const prekeyId = pool[randomIndex(pool.length)]!;
  // fsRecipientFromBundle re-verifies the directory + bundle signature and the org
  // match, so a tampered or wrong-org bundle resolves to nothing (fails closed).
  return (
    fsRecipientFromBundle(opts.directory, bundle, opts.recipientOrg, prekeyId, opts.rootPublicKeyHex, when) ??
    "bundle-not-verified"
  );
}

/** Encrypt a traveler to a directory-attested recipient. Verifies the directory
 *  against the trust root BEFORE resolving the recipient — `recipientByOrg` /
 *  `fsRecipientFromBundle` resolve attested keys, but skipping the directory check
 *  would still let a sealer trust an attacker-substituted directory. Returns the
 *  envelope, whether forward secrecy was used (always reported; never a silent
 *  downgrade), the one-time prekey it spent, and — when it fell back — why.
 *
 *  ONE-TIME PREKEYS ARE THE SENDER'S TO TRACK. A forward-secret seal spends one prekey
 *  of the recipient's bundle and returns its id as `prekeyId`; pass every id you have
 *  been given back in `excludePrekeyIds` on later seals to the same bundle (see
 *  SealOptions). When they are all spent the seal says so (`prekeys-exhausted`) instead
 *  of reusing one.
 *
 *  What this does NOT solve: two DIFFERENT senders. The bundle is a static public file
 *  with no reservation, so two senders can each pick the same prekey; the envelope the
 *  recipient opens second is unopenable, and neither sender is told. So can anyone
 *  holding the bundle spend prekeys on purpose with junk envelopes. Preventing either
 *  needs a party that hands each sender a different prekey — a server — which a file
 *  format does not have. Tracking removes the loss a sender inflicts on itself. */
export async function sealTraveler(traveler: Traveler, opts: SealOptions): Promise<SealResult> {
  const when = opts.at ?? new Date();
  if (!verifyDirectory(opts.directory, opts.rootPublicKeyHex, when)) {
    throw new Error("sealTraveler: key directory does not verify against the trust root");
  }
  const zipBytes = new Uint8Array(await (await travelerToZip(traveler)).arrayBuffer());

  // Prefer forward secrecy when a verifying bundle with a usable prekey exists.
  const fs = resolveFsRecipient(opts, when);
  if (typeof fs !== "string") {
    return {
      envelope: sealFsEnvelope(zipBytes, [fs]),
      forwardSecret: true,
      prekeyId: fs.prekey_id,
    };
  }
  if (opts.requireForwardSecret) {
    throw new Error(
      `sealTraveler: forward secrecy required but no verifying prekey bundle with a usable prekey is available (${fs})`,
    );
  }

  // Explicit, reported fallback to the static envelope.
  const recipient = recipientByOrg(opts.directory, opts.recipientOrg, when);
  if (!recipient) {
    throw new Error(`sealTraveler: no in-window ML-KEM recipient for ${opts.recipientOrg}`);
  }
  return { envelope: sealEnvelope(zipBytes, [recipient]), forwardSecret: false, staticReason: fs };
}

/** A decrypted traveler whose one-time prekey has not been spent yet. */
export type OpenedTraveler = {
  traveler: Traveler;
  /** Whether the envelope was forward-secret (a one-time prekey is involved). */
  forwardSecret: boolean;
  /** Spend the one-time prekey this envelope used, and persist that. Call it once the
   *  traveler has been ADMITTED (or when the envelope is being discarded for good).
   *  Idempotent; a no-op for a static envelope. If storing the deletion fails, this
   *  rejects with nothing changed — the prekey is still held, in the session and in the
   *  stored blob — and it can be called again. */
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
    // Store first, then forget. The blob without this prekey is written while the
    // session still holds the prekey; only when the write has succeeded is it deleted
    // here. A write that fails therefore changes nothing anywhere — the session and the
    // stored blob still agree, the caller is told, and commit() can be called again. (It
    // used to delete in memory first: after a failed write the session had lost a prekey
    // the stored blob still had, and a second commit() did nothing at all.)
    let done = false;
    let running: Promise<void> | undefined;
    const spend = async (): Promise<void> => {
      // Already gone (another open of the same envelope committed first): nothing to do.
      if (keystore.peekPrekey(r.prekey_id)) {
        if (opts?.persistKeystore) await opts.persistKeystore(keystore.withoutPrekey(r.prekey_id));
        keystore.consumePrekey(r.prekey_id);
      }
      done = true;
    };
    const commit = (): Promise<void> => {
      if (done) return Promise.resolve();
      // One spend at a time: a second call while the first is being stored waits for it
      // rather than writing again. A failed spend clears the way for a retry.
      running ??= spend().finally(() => {
        running = undefined;
      });
      return running;
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
