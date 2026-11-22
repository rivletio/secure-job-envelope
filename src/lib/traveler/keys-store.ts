/** Desk key custody + trust anchor — the browser-side state for the encrypted
 *  transport.
 *
 *  Persisted (localStorage, one item): the ENCRYPTED identity keystore blob; the
 *  PUBLIC, signed trust anchor (root public key + directory + prekey bundles); the
 *  newest directory this desk has accepted under each root (the rollback mark); and
 *  which one-time prekeys this desk has already sealed to. All safe at rest — the
 *  keystore secret is encrypted under the passphrase, the rest is public or
 *  bookkeeping.
 *
 *  In memory only (never persisted): the unlocked keystore. The plaintext ML-KEM
 *  secret exists only while unlocked, for the life of the tab. Lock promptly; an XSS
 *  on an unlocked desk can read the in-memory secret (ML-KEM runs in JS). The desk
 *  still never holds SIGNING keys — signing a prekey bundle happens off the desk.
 *
 *  Sealing (encrypt-to-recipient) needs only the trust anchor's public keys, so it
 *  works locked. Opening a received `.sje` needs the unlocked keystore.
 *
 *  THE TRUST ANCHOR IS WHAT EVERY VERDICT STANDS ON, so replacing it is never silent
 *  and never goes backwards (`reviewTrustChange` / `setTrust`):
 *    - a directory OLDER than one already accepted under the same root is refused —
 *      going back would let a since-revoked key authenticate again;
 *    - a DIFFERENT root replaces the held one only with an explicit confirmation of
 *      the new root's fingerprint, and so does the first root a desk ever loads.
 *  The rollback mark is this desk's own memory. A desk whose storage was cleared has
 *  none: the first directory it is given cannot be compared with anything.
 *
 *  STORAGE IS NOT ASSUMED TO WORK, AND THIS TAB IS NOT ASSUMED TO BE ALONE:
 *    - every write is read back; a write the browser dropped (quota, blocked storage)
 *      is reported (`useCustodyStatus`) and the action that needed it fails, instead
 *      of the desk claiming a one-time prekey is gone when it is still on disk;
 *    - a tab never writes over stored data it has not seen. Each tab re-encrypts the
 *      keystore from ITS copy of the vault, so a tab that missed another tab's change
 *      would write spent prekeys back and drop newly minted ones. When another tab
 *      changes the stored data, this tab adopts it — and if the keystore blob itself
 *      changed, locks its unlocked session (`syncKeysFromStorage`).
 */
import { create } from "zustand";
import { persist, createJSONStorage, type StateStorage } from "zustand/middleware";
import {
  createIdentity as createIdentityKs,
  keystoreShapeError,
  unlock as unlockKs,
  type Keystore,
  type Unlocked,
  type DirectoryEntryPublic,
  type PublicPrekey,
} from "./keystore.ts";
import { isoDateTimeMs } from "./datetime.ts";
import { isDemoTrustRoot } from "./demo-trust.ts";
import { directoryShapeError, verifyDirectory, type Directory } from "./directory.ts";
import { formatFingerprint, rootDigest } from "./fingerprint.ts";
import {
  recordPrekeyUse as recordInLedger,
  sanitizePrekeyLedger,
  usedPrekeyIds,
  type PrekeyLedger,
} from "./prekey-ledger.ts";
import { prekeyBundleShapeError, verifyPrekeyBundle, type PrekeyBundle } from "./prekeys.ts";
import { safeStorage } from "./store.ts";

/** The localStorage item everything here lives in. */
export const KEYS_STORAGE_KEY = "sje-keys-001";

/** Public, signed trust material the desk needs to resolve and verify recipients. */
export type TrustAnchor = {
  rootPublicKeyHex: string;
  directory: Directory;
  bundles: Record<string, PrekeyBundle>; // org_id -> verified bundle
};

/** A trust anchor as offered to the desk (a pasted file, the demo anchor). */
export type TrustAnchorInput = {
  rootPublicKeyHex: string;
  directory: Directory;
  bundles?: Record<string, PrekeyBundle>;
};

/** Per trust root (`rootDigest`): `issued_at` of the newest directory this desk has
 *  accepted under it. Outlives the anchor itself — clearing or replacing the anchor
 *  does not make the desk forget what it has seen. */
export type TrustMarks = Record<string, string>;

/** Most roots remembered; beyond that the one accepted longest ago is forgotten. */
export const MAX_TRUST_MARKS = 64;

/* ------------------------------------------------------------------ storage ---- */

/** What this desk knows about its own persistence, and what other tabs did to it.
 *  Not persisted; a separate store so that reporting a failed write is not itself a
 *  write. */
export type CustodyNotice = {
  id: number;
  kind: "keystore-changed-elsewhere" | "keystore-removed-elsewhere" | "trust-changed-elsewhere";
  /** One line (a toast). */
  summary: string;
  /** What happened and why, in full (the keys page). */
  message: string;
};
type CustodyStatus = {
  /** Set while the stored data is NOT what this tab holds: the browser dropped the last
   *  write. Cleared by the next write that is read back intact. */
  storageError?: string;
  /** Things that happened to this tab from outside it, oldest first. */
  notices: CustodyNotice[];
  dismissNotice: (id: number) => void;
};
export const useCustodyStatus = create<CustodyStatus>()((set) => ({
  storageError: undefined,
  notices: [],
  dismissNotice: (id) => set((s) => ({ notices: s.notices.filter((n) => n.id !== id) })),
}));

const NOT_SAVED =
  "This browser did not save the desk's key data — its storage is full or blocked. What this tab " +
  "shows is newer than what is stored.";

let noticeSeq = 0;
function notify(kind: CustodyNotice["kind"], summary: string, message: string): void {
  useCustodyStatus.setState((s) => ({
    notices: [...s.notices, { id: ++noticeSeq, kind, summary, message }].slice(-5),
  }));
}
function setStorageError(message: string | undefined): void {
  if (useCustodyStatus.getState().storageError !== message) {
    useCustodyStatus.setState({ storageError: message });
  }
}

/** Read the stored item. `{ raw: null }` means nothing is stored; `undefined` means
 *  storage could not be READ at all (blocked, disabled) — which is not the same thing,
 *  and must never be taken for "someone removed it". */
function readStored(name: string): { raw: string | null } | undefined {
  try {
    return { raw: typeof localStorage === "undefined" ? null : localStorage.getItem(name) };
  } catch {
    return undefined;
  }
}

/** What this tab last saw stored under KEYS_STORAGE_KEY (undefined: it has not managed
 *  to look yet). */
let seen: { raw: string | null } | undefined;
/** How the most recent write went. */
let lastWrite: "saved" | "not-saved" | "changed-elsewhere" = "saved";

/** localStorage with two rules the plain wrapper does not have.
 *
 *  1. A write is read back. `safeStorage.setItem` swallows a quota or security error by
 *     design (it must not crash the desk), which made a dropped write look like a
 *     successful one. Here the outcome is recorded, and reported.
 *  2. A write never replaces a value this tab has not seen. If the stored text is not
 *     what this tab last read or wrote, someone else changed it, and the write is
 *     withheld (the caller then adopts the stored state instead). */
const custodyStorage: StateStorage = {
  getItem(name) {
    const now = readStored(name);
    if (!now) return null; // cannot be read: nothing to load (and nothing learned)
    seen = now;
    if (now.raw === null) return null;
    try {
      JSON.parse(now.raw);
      return now.raw;
    } catch {
      return null; // text that is not JSON is treated as absent, never as a crash
    }
  },
  setItem(name, value) {
    const now = readStored(name);
    if (now && seen && now.raw !== seen.raw) {
      lastWrite = "changed-elsewhere";
      return;
    }
    safeStorage.setItem(name, value);
    const back = readStored(name);
    if (back && back.raw === value) {
      seen = back;
      lastWrite = "saved";
      setStorageError(undefined);
    } else {
      lastWrite = "not-saved";
      setStorageError(NOT_SAVED);
    }
  },
  removeItem(name) {
    safeStorage.removeItem(name);
    seen = readStored(name) ?? seen;
  },
};

/** The stored key data could not be written: the action that needed it did not happen
 *  on disk. */
export class KeystoreNotSavedError extends Error {
  constructor(what: string) {
    super(`${what} The change was not saved: this browser's storage is full or blocked.`);
    this.name = "KeystoreNotSavedError";
  }
}

/** Another tab or window changed the stored key data first; this tab adopted it (and
 *  locked, if the keystore blob itself changed) instead of writing over it. */
export class KeystoreChangedElsewhereError extends Error {
  constructor() {
    super(
      "Another tab or window changed this desk's stored keys, so this tab reloaded them instead of " +
        "writing over them — and locked, if the keystore itself changed. Unlock again and retry.",
    );
    this.name = "KeystoreChangedElsewhereError";
  }
}

/* -------------------------------------------------------------------- trust ---- */

/** A trust root as a person identifies it. */
export type RootIdentity = {
  /** `rootDigest` — the root's identity. */
  digest: string;
  /** The short form to compare out of band. */
  fingerprint: string;
  /** The root whose secret key is public (`isDemoTrustRoot`). */
  demo: boolean;
};

/** What loading an anchor would do — computed without doing it. */
export type TrustReview = {
  /** `first-load`: the desk holds no anchor. `same-root`: a directory under the root it
   *  already holds. `root-change`: a different root would replace the held one. */
  kind: "first-load" | "same-root" | "root-change";
  /** True for `first-load` and `root-change`: `setTrust` needs the root confirmed. */
  needsConfirmation: boolean;
  /** The root being loaded, and its directory. */
  root: RootIdentity;
  issuedAt: string;
  validUntil: string;
  entries: number;
  /** The anchor the desk holds now, if any. */
  held?: RootIdentity & { issuedAt: string };
  /** `issued_at` of the newest directory this desk has accepted under the root being
   *  loaded. Undefined: the desk has no record of this root — a first load, or its
   *  storage was cleared — so it CANNOT tell whether this directory is the newest. */
  knownIssuedAt?: string;
  /** Fingerprints of the OTHER roots this desk has accepted before, oldest first. A
   *  desk that cleared its anchor and is now offered a root it has never seen can at
   *  least be shown which roots it used to trust. */
  otherKnownRoots: string[];
  /** Prekey bundles offered with the anchor: which verify (kept) and which do not. */
  bundles: { kept: string[]; dropped: string[] };
};

/** `setTrust` was asked to adopt a root nobody confirmed. Carries the review to show. */
export class TrustConfirmationRequired extends Error {
  readonly review: TrustReview;
  constructor(review: TrustReview) {
    super(
      review.kind === "root-change"
        ? "Replacing the trust root needs explicit confirmation of the new root's fingerprint."
        : "Loading a trust root needs explicit confirmation of its fingerprint.",
    );
    this.name = "TrustConfirmationRequired";
    this.review = review;
  }
}

/** The directory offered is older than one this desk already accepted under that root. */
export class TrustRollbackError extends Error {
  constructor(offered: string, known: string) {
    super(
      `Refused: this directory was issued ${offered}, but this desk has already accepted one issued ` +
        `${known} under the same trust root. An older directory can bring back a key that has since ` +
        `been revoked.`,
    );
    this.name = "TrustRollbackError";
  }
}

function rootIdentity(rootPublicKeyHex: string, digest: string): RootIdentity {
  return { digest, fingerprint: formatFingerprint(digest), demo: isDemoTrustRoot(rootPublicKeyHex) };
}

/** Why an anchor that failed `verifyDirectory` failed, for the person who pasted it:
 *  not a directory at all, outside its own validity window, or not signed by this root.
 *  (`verifyDirectory` answers yes or no; these are the same checks, in its order.) */
function whyNotVerified(anchor: TrustAnchorInput, digest: string | null, at: Date): string {
  if (digest === null) return "The root public key is not hex: the directory does not verify against it.";
  const shape = directoryShapeError(anchor.directory);
  if (shape !== null) return `This is not a well-formed directory (${shape}), so it does not verify.`;
  const issued = isoDateTimeMs(anchor.directory.issued_at);
  const until = isoDateTimeMs(anchor.directory.valid_until);
  const t = at.getTime();
  if (issued !== null && until !== null && !(issued <= t && t < until)) {
    return (
      `This directory is valid from ${anchor.directory.issued_at} until ${anchor.directory.valid_until}, ` +
      "which does not include now, so it does not verify."
    );
  }
  return "Directory does not verify against this root public key.";
}

/** Decide what loading `anchor` would do to a desk in state `state`, without changing
 *  anything (so it is safe to call while rendering).
 *
 *  Throws if the anchor can never be loaded: its directory does not verify against its
 *  root at `at`, or (`TrustRollbackError`) it is older than a directory already accepted
 *  under the same root. A directory with the SAME `issued_at` as the mark is accepted:
 *  that is the same directory being loaded again. */
export function reviewTrustChange(
  state: { trust?: TrustAnchor; trustMarks: TrustMarks },
  anchor: TrustAnchorInput,
  at: Date = new Date(),
): TrustReview {
  const digest = rootDigest(anchor.rootPublicKeyHex);
  if (digest === null || !verifyDirectory(anchor.directory, anchor.rootPublicKeyHex, at)) {
    throw new Error(whyNotVerified(anchor, digest, at));
  }
  const issued = isoDateTimeMs(anchor.directory.issued_at)!; // a verified directory has one
  const knownIssuedAt = Object.hasOwn(state.trustMarks, digest) ? state.trustMarks[digest] : undefined;
  const known = knownIssuedAt === undefined ? null : isoDateTimeMs(knownIssuedAt);
  if (known !== null && issued < known) {
    throw new TrustRollbackError(anchor.directory.issued_at, knownIssuedAt!);
  }
  const heldDigest = state.trust ? rootDigest(state.trust.rootPublicKeyHex) : null;
  const kind = !state.trust ? "first-load" : heldDigest === digest ? "same-root" : "root-change";
  const kept: string[] = [];
  const dropped: string[] = [];
  for (const [org, b] of Object.entries(anchor.bundles ?? {})) {
    const ok =
      prekeyBundleShapeError(b) === null &&
      b.org_id === org &&
      verifyPrekeyBundle(b, anchor.directory, anchor.rootPublicKeyHex, at) !== undefined;
    (ok ? kept : dropped).push(org);
  }
  return {
    kind,
    needsConfirmation: kind !== "same-root",
    root: rootIdentity(anchor.rootPublicKeyHex, digest),
    issuedAt: anchor.directory.issued_at,
    validUntil: anchor.directory.valid_until,
    entries: anchor.directory.entries.length,
    ...(state.trust && heldDigest !== null
      ? {
          held: {
            ...rootIdentity(state.trust.rootPublicKeyHex, heldDigest),
            issuedAt: state.trust.directory.issued_at,
          },
        }
      : {}),
    ...(knownIssuedAt !== undefined && known !== null ? { knownIssuedAt } : {}),
    otherKnownRoots: Object.keys(state.trustMarks)
      .filter((d) => d !== digest)
      .map(formatFingerprint),
    bundles: { kept, dropped },
  };
}

/** Rehydrate defensively: keep a persisted trust anchor only if it is well-shaped, so
 *  a malformed or drifted blob (schema drift across app versions, hand-edited or
 *  corrupted localStorage) does not crash the routes that read `directory.entries` /
 *  `bundles` on first render. Mirrors `sanitizeTravelers` in store.ts. `sealTraveler`
 *  re-verifies the directory against the root before any key is used, so shape — not
 *  signature — is the crash-safety concern here. */
export function sanitizeTrust(t: unknown): TrustAnchor | undefined {
  if (!t || typeof t !== "object") return undefined;
  const a = t as Partial<TrustAnchor>;
  const dir = a.directory as Directory | undefined;
  // The persisted directory is held to the exact directory shape, not just "has an
  // entries array": everything that renders or resolves entries may then rely on it.
  // The root must at least be hex-encoded bytes (so it has a fingerprint to show).
  if (rootDigest(a.rootPublicKeyHex) === null || directoryShapeError(dir) !== null || !dir) {
    return undefined;
  }
  const bundles: Record<string, PrekeyBundle> = {};
  if (a.bundles && typeof a.bundles === "object" && !Array.isArray(a.bundles)) {
    for (const [org, b] of Object.entries(a.bundles)) {
      if (prekeyBundleShapeError(b) === null && b.org_id === org) bundles[org] = b;
    }
  }
  return { rootPublicKeyHex: a.rootPublicKeyHex as string, directory: dir, bundles };
}

/** Rehydrate the rollback marks defensively: a root digest -> a canonical datetime. */
export function sanitizeTrustMarks(v: unknown): TrustMarks {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return {};
  const out: [string, string][] = [];
  for (const [digest, issuedAt] of Object.entries(v)) {
    if (/^[0-9a-f]{96}$/.test(digest) && typeof issuedAt === "string" && isoDateTimeMs(issuedAt) !== null) {
      out.push([digest, issuedAt]);
    }
  }
  return Object.fromEntries(out.slice(-MAX_TRUST_MARKS));
}

/** `marks` with `digest` raised to `issuedAt` (never lowered), most recent root last. */
function raiseMark(marks: TrustMarks, digest: string, issuedAt: string): TrustMarks {
  const had = Object.hasOwn(marks, digest) ? marks[digest]! : undefined;
  const keep = had !== undefined && (isoDateTimeMs(had) ?? -Infinity) >= (isoDateTimeMs(issuedAt) ?? -Infinity);
  const rest = Object.entries(marks).filter(([d]) => d !== digest);
  return Object.fromEntries([...rest, [digest, keep ? had : issuedAt]].slice(-MAX_TRUST_MARKS));
}

/* -------------------------------------------------------------------- store ---- */

type KeysState = {
  identity?: Keystore; // encrypted blob (persisted)
  trust?: TrustAnchor; // public/signed (persisted)
  trustMarks: TrustMarks; // rollback memory (persisted)
  prekeyLedger: PrekeyLedger; // one-time prekeys this desk has sealed to (persisted)
  unlocked?: Unlocked; // in-memory only
  hydrated: boolean;
  setHydrated: (v: boolean) => void;
  isUnlocked: () => boolean;
  /** Create a fresh identity, leave it unlocked, and return the public directory
   *  entry to publish. Replaces any existing identity. Throws — and creates nothing —
   *  if the browser does not store it: an identity that exists only in this tab would
   *  be published and then lost. */
  createIdentity: (passphrase: string, orgId?: string) => Promise<DirectoryEntryPublic>;
  /** Adopt an existing encrypted keystore blob (e.g. one minted by the MCP/CLI). */
  importIdentity: (blob: Keystore) => void;
  clearIdentity: () => void;
  unlock: (passphrase: string) => Promise<void>;
  lock: () => void;
  /** Persist a keystore blob returned by a mutating op (e.g. a consumed prekey) — or
   *  THROW. It throws `KeystoreNotSavedError` if the browser did not store the blob (the
   *  one-time prekey is then still on disk, and the desk says so), and
   *  `KeystoreChangedElsewhereError` if another tab changed the stored keystore first
   *  (this tab's copy is out of date; writing it would undo that tab's work). */
  persistKeystore: (blob: Keystore) => void;
  /** Mint one-time prekeys (requires unlock) and persist the updated blob. Returns
   *  the public prekeys to publish in a signed bundle (signed off the desk). Throws
   *  rather than return prekeys whose secrets were not stored. */
  addPrekeys: (n: number) => PublicPrekey[];
  /** Write the current state to storage again (after a failed write). True if it is
   *  now stored. */
  retrySave: () => boolean;
  /** Load a trust anchor. The directory (and each bundle) must verify against the root;
   *  a directory older than one already accepted under that root is refused
   *  (`TrustRollbackError`); and unless it is a newer-or-same directory under the root
   *  already held, `confirmedRoot` must be the digest of the root being loaded — the
   *  one whose fingerprint the person was shown (`reviewTrustChange`) — or this throws
   *  `TrustConfirmationRequired`. */
  setTrust: (anchor: TrustAnchorInput, opts?: { at?: Date; confirmedRoot?: string }) => TrustReview;
  /** Drop the anchor. The rollback marks are kept. */
  clearTrust: () => void;
  /** Record that this desk sealed to `prekeyId` of `bundle`, so it is never chosen
   *  again. Throws if another tab used that prekey in the meantime, or if the record
   *  could not be stored — in either case the envelope just sealed must not be sent. */
  recordPrekeyUse: (bundle: PrekeyBundle, prekeyId: string) => void;
};

function sameJson(a: unknown, b: unknown): boolean {
  return a === b || JSON.stringify(a) === JSON.stringify(b);
}

/** If another tab or window has rewritten this desk's key data since this tab last
 *  looked, adopt it before doing anything else. Returns true iff the keystore blob
 *  changed (an unlocked session here has been locked). */
function ensureFresh(): boolean {
  const now = readStored(KEYS_STORAGE_KEY);
  if (!now || !seen || now.raw === seen.raw) return false;
  return syncKeysFromStorage().keystoreChanged;
}

/** After a `set`: throw unless that write reached storage. If another tab changed the
 *  stored data first (the write was withheld), this tab adopts what is stored. */
function requireSaved(what: string): void {
  if (lastWrite === "changed-elsewhere") {
    syncKeysFromStorage();
    throw new KeystoreChangedElsewhereError();
  }
  if (lastWrite === "not-saved") throw new KeystoreNotSavedError(what);
}

/** After a `set` whose loss on a failed write is tolerable (it is reported, not
 *  fatal): still never proceed over a foreign change. */
function requireNotOverwritten(): void {
  if (lastWrite === "changed-elsewhere") {
    syncKeysFromStorage();
    throw new KeystoreChangedElsewhereError();
  }
}

export const useKeysStore = create<KeysState>()(
  persist(
    (set, get) => ({
      identity: undefined,
      trust: undefined,
      trustMarks: {},
      prekeyLedger: {},
      unlocked: undefined,
      hydrated: false,
      setHydrated: (v) => set({ hydrated: v }),
      isUnlocked: () => Boolean(get().unlocked),
      createIdentity: async (passphrase, orgId) => {
        const { keystore, directoryEntry } = await createIdentityKs({
          passphrase,
          ...(orgId ? { orgId } : {}),
        });
        const u = await unlockKs(keystore, passphrase);
        ensureFresh(); // the derivations took a while; another tab may have written
        const before = { identity: get().identity, unlocked: get().unlocked };
        set({ identity: keystore, unlocked: u });
        if (lastWrite === "not-saved") {
          // Not stored: undo, so the desk does not hand out a directory entry for an
          // identity that will not be here after a reload.
          u.lock();
          set(before);
          throw new KeystoreNotSavedError("The new identity was not created.");
        }
        before.unlocked?.lock(); // replaced — or, if storage changed under us, out of date
        if (lastWrite === "changed-elsewhere") u.lock();
        requireSaved("");
        return directoryEntry;
      },
      importIdentity: (blob) => {
        if (keystoreShapeError(blob) !== null) throw new Error("Not a keystore this desk can read.");
        ensureFresh();
        const before = { identity: get().identity, unlocked: get().unlocked };
        set({ identity: blob, unlocked: undefined });
        if (lastWrite === "not-saved") {
          set(before);
          throw new KeystoreNotSavedError("The keystore was not imported.");
        }
        before.unlocked?.lock();
        requireSaved("");
      },
      clearIdentity: () => {
        ensureFresh();
        get().unlocked?.lock();
        set({ identity: undefined, unlocked: undefined });
        requireSaved("The keystore is removed from this tab, but it is still in this browser's storage.");
      },
      unlock: async (passphrase) => {
        ensureFresh();
        const id = get().identity;
        if (!id) throw new Error("No identity on this desk — create one first.");
        const u = await unlockKs(id, passphrase); // uniform error on wrong passphrase
        // The derivation took a while. If the stored keystore changed meanwhile, `u`
        // is a session over a blob that is no longer the stored one: discard it.
        if (ensureFresh() || get().identity !== id) {
          u.lock();
          throw new KeystoreChangedElsewhereError();
        }
        get().unlocked?.lock();
        if (u.needsUpgrade) {
          // An older keystore format (or KDF cost): write it back in the current one
          // now, rather than whenever a prekey next happens to be minted or consumed.
          set({ identity: u.reseal(), unlocked: u });
          requireNotOverwritten();
        } else {
          set({ unlocked: u });
        }
      },
      lock: () => {
        get().unlocked?.lock();
        set({ unlocked: undefined });
      },
      persistKeystore: (blob) => {
        if (keystoreShapeError(blob) !== null) throw new Error("Not a keystore this desk can read.");
        if (ensureFresh()) throw new KeystoreChangedElsewhereError();
        // The new blob stays in memory even if the write fails — it is what a later
        // write (or `retrySave`) must store — and the failure is reported, loudly.
        set({ identity: blob });
        requireSaved(
          "The keystore was NOT updated on disk: a one-time prekey that was just used is still stored there.",
        );
      },
      addPrekeys: (n) => {
        if (ensureFresh()) throw new KeystoreChangedElsewhereError();
        const u = get().unlocked;
        if (!u) throw new Error("Unlock your identity first.");
        const { keystore, prekeys } = u.addPrekeys(n);
        set({ identity: keystore });
        requireSaved("The new prekeys were not stored, so do not publish them.");
        return prekeys;
      },
      retrySave: () => {
        ensureFresh();
        set({});
        if (lastWrite === "changed-elsewhere") syncKeysFromStorage();
        return lastWrite === "saved";
      },
      setTrust: (anchor, opts) => {
        ensureFresh();
        const when = opts?.at ?? new Date();
        const review = reviewTrustChange(get(), anchor, when);
        if (review.needsConfirmation && opts?.confirmedRoot !== review.root.digest) {
          throw new TrustConfirmationRequired(review);
        }
        // Keep only bundles that verify against the same root (fail closed).
        const bundles: Record<string, PrekeyBundle> = {};
        for (const org of review.bundles.kept) bundles[org] = anchor.bundles![org]!;
        set({
          trust: {
            rootPublicKeyHex: anchor.rootPublicKeyHex.toLowerCase(),
            directory: anchor.directory,
            bundles,
          },
          trustMarks: raiseMark(get().trustMarks, review.root.digest, anchor.directory.issued_at),
        });
        requireNotOverwritten();
        return review;
      },
      clearTrust: () => {
        ensureFresh();
        set({ trust: undefined });
      },
      recordPrekeyUse: (bundle, prekeyId) => {
        ensureFresh();
        if (usedPrekeyIds(get().prekeyLedger, bundle).includes(prekeyId)) {
          throw new Error(
            "That one-time prekey was used from another tab in the meantime. Nothing was sent — seal again.",
          );
        }
        set({ prekeyLedger: recordInLedger(get().prekeyLedger, bundle, prekeyId) });
        requireSaved(
          "The one-time prekey could not be recorded as used, so nothing was sent (after a reload this desk would use it again).",
        );
      },
    }),
    {
      name: KEYS_STORAGE_KEY,
      skipHydration: true,
      storage: createJSONStorage(() => custodyStorage),
      // Persist ONLY the encrypted blob and the public trust material — never the
      // unlocked session (it holds the plaintext secret and live functions).
      partialize: (s) => ({
        identity: s.identity,
        trust: s.trust,
        trustMarks: s.trustMarks,
        prekeyLedger: s.prekeyLedger,
      }),
      // Runs on the first load AND whenever another tab changed the stored data
      // (`syncKeysFromStorage`): this tab becomes what a reload would produce — except
      // that an unlocked session survives iff the keystore blob is the one it was
      // unlocked from.
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Record<string, unknown>;
        const trustMarks = sanitizeTrustMarks(p.trustMarks);
        let trust = sanitizeTrust(p.trust);
        if (trust) {
          const digest = rootDigest(trust.rootPublicKeyHex)!;
          const issued = isoDateTimeMs(trust.directory.issued_at)!;
          const mark = Object.hasOwn(trustMarks, digest) ? isoDateTimeMs(trustMarks[digest]!) : null;
          if (mark === null) {
            // An anchor stored before marks existed: the mark starts at what is held.
            trustMarks[digest] = trust.directory.issued_at;
          } else if (issued < mark) {
            // Older than a directory this desk has accepted under the same root — the
            // stored anchor went backwards. Not loaded.
            trust = undefined;
          }
        }
        // The keystore blob is kept exactly as stored, even one this version cannot
        // read (a newer format, say): dropping it here would have the next write
        // erase it from storage.
        const sameBlob = sameJson(p.identity, current.identity);
        return {
          ...current,
          identity: sameBlob ? current.identity : (p.identity as Keystore | undefined),
          trust,
          trustMarks,
          prekeyLedger: sanitizePrekeyLedger(p.prekeyLedger),
          unlocked: sameBlob ? current.unlocked : undefined,
        };
      },
      onRehydrateStorage: () => {
        watchOnce();
      },
    },
  ),
);

/* ---------------------------------------------------------------- cross-tab ---- */

/** Make this tab's state what storage holds now — what a reload would produce — after
 *  another tab or window changed it. If the keystore blob itself changed, this tab's
 *  unlocked session is LOCKED: its copy of the vault predates the change, and anything
 *  it re-sealed would put spent prekeys back and drop new ones. The person is told why
 *  (`useCustodyStatus().notices`). */
export function syncKeysFromStorage(): { keystoreChanged: boolean; trustRootChanged: boolean } {
  // Storage that cannot be read right now says nothing about what is stored: keep what
  // this tab holds rather than mistake "unreadable" for "removed".
  if (!readStored(KEYS_STORAGE_KEY)) return { keystoreChanged: false, trustRootChanged: false };
  const before = useKeysStore.getState();
  void useKeysStore.persist.rehydrate(); // synchronous for localStorage
  const after = useKeysStore.getState();

  const keystoreChanged = after.identity !== before.identity;
  if (keystoreChanged) {
    before.unlocked?.lock();
    if (before.identity && !after.identity) {
      notify(
        "keystore-removed-elsewhere",
        "This desk's keystore was removed in another tab.",
        "This desk's keystore was removed in another tab or window, so it is gone from this tab too.",
      );
    } else if (before.unlocked) {
      notify(
        "keystore-changed-elsewhere",
        "This tab was locked: another tab changed this desk's keystore. Details in Keys.",
        "This tab was locked because another tab or window changed this desk's keystore — for example by " +
          "opening a forward-secret envelope (which uses up a one-time prekey) or minting prekeys. Every tab " +
          "re-encrypts the keystore from its own copy, so an out-of-date tab would write spent prekeys back " +
          "and drop new ones. This tab has reloaded the stored keystore; unlock again to continue.",
      );
    }
  }

  const rootBefore = before.trust ? rootDigest(before.trust.rootPublicKeyHex) : null;
  const rootAfter = after.trust ? rootDigest(after.trust.rootPublicKeyHex) : null;
  const trustRootChanged = rootBefore !== rootAfter;
  if (trustRootChanged) {
    const fp = (d: string | null) => (d === null ? "none" : formatFingerprint(d));
    notify(
      "trust-changed-elsewhere",
      "The trust anchor was changed in another tab. Details in Keys.",
      `The trust anchor was changed in another tab or window (root ${fp(rootBefore)} → ${fp(rootAfter)}). ` +
        "Every verdict on this desk now depends on the new one.",
    );
  }
  return { keystoreChanged, trustRootChanged };
}

/** Listen for other tabs and windows changing this desk's stored key data (`storage`
 *  events fire only in documents OTHER than the one that wrote). `key === null` is a
 *  whole-storage clear. Returns a function that stops listening. */
export function watchKeysStorage(target: {
  addEventListener: (type: "storage", listener: (e: Event) => void) => void;
  removeEventListener: (type: "storage", listener: (e: Event) => void) => void;
}): () => void {
  const onStorage = (e: Event) => {
    const key = (e as StorageEvent).key;
    if (key === KEYS_STORAGE_KEY || key === null) syncKeysFromStorage();
  };
  target.addEventListener("storage", onStorage);
  return () => target.removeEventListener("storage", onStorage);
}

let watching = false;
/** Start watching once this tab has loaded its own copy (first hydration, in a browser). */
function watchOnce(): void {
  if (watching || typeof window === "undefined" || typeof window.addEventListener !== "function") return;
  watching = true;
  watchKeysStorage(window);
}
