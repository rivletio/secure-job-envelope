/** Desk key custody + trust anchor — the browser-side state for the encrypted
 *  transport.
 *
 *  Persisted (localStorage): the ENCRYPTED identity keystore blob and the PUBLIC,
 *  signed trust anchor (root public key + directory + prekey bundles). Both are safe
 *  at rest — the keystore secret is encrypted under the passphrase, and the trust
 *  anchor is public, signed material.
 *
 *  In memory only (never persisted): the unlocked keystore. The plaintext ML-KEM
 *  secret exists only while unlocked, for the life of the tab. Lock promptly; an XSS
 *  on an unlocked desk can read the in-memory secret (ML-KEM runs in JS). The desk
 *  still never holds SIGNING keys — signing a prekey bundle happens off the desk.
 *
 *  Sealing (encrypt-to-recipient) needs only the trust anchor's public keys, so it
 *  works locked. Opening a received `.sje` needs the unlocked keystore.
 */
import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import {
  createIdentity as createIdentityKs,
  unlock as unlockKs,
  type Keystore,
  type Unlocked,
  type DirectoryEntryPublic,
  type PublicPrekey,
} from "./keystore.ts";
import { verifyDirectory, type Directory } from "./directory.ts";
import { verifyPrekeyBundle, type PrekeyBundle } from "./prekeys.ts";
import { safeStorage } from "./store.ts";

/** Public, signed trust material the desk needs to resolve and verify recipients. */
export type TrustAnchor = {
  rootPublicKeyHex: string;
  directory: Directory;
  bundles: Record<string, PrekeyBundle>; // org_id -> verified bundle
};

type KeysState = {
  identity?: Keystore; // encrypted blob (persisted)
  trust?: TrustAnchor; // public/signed (persisted)
  unlocked?: Unlocked; // in-memory only
  hydrated: boolean;
  setHydrated: (v: boolean) => void;
  isUnlocked: () => boolean;
  /** Create a fresh identity, leave it unlocked, and return the public directory
   *  entry to publish. Replaces any existing identity. */
  createIdentity: (passphrase: string, orgId?: string) => Promise<DirectoryEntryPublic>;
  /** Adopt an existing encrypted keystore blob (e.g. one minted by the MCP/CLI). */
  importIdentity: (blob: Keystore) => void;
  clearIdentity: () => void;
  unlock: (passphrase: string) => Promise<void>;
  lock: () => void;
  /** Persist a keystore blob returned by a mutating op (e.g. a consumed prekey). */
  persistKeystore: (blob: Keystore) => void;
  /** Mint one-time prekeys (requires unlock) and persist the updated blob. Returns
   *  the public prekeys to publish in a signed bundle (signed off the desk). */
  addPrekeys: (n: number) => PublicPrekey[];
  /** Load a trust anchor, verifying the directory (and each bundle) against the root
   *  before accepting it. Throws if the directory does not verify. */
  setTrust: (
    anchor: { rootPublicKeyHex: string; directory: Directory; bundles?: Record<string, PrekeyBundle> },
    at?: Date,
  ) => void;
  clearTrust: () => void;
};

export const useKeysStore = create<KeysState>()(
  persist(
    (set, get) => ({
      identity: undefined,
      trust: undefined,
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
        get().unlocked?.lock();
        set({ identity: keystore, unlocked: u });
        return directoryEntry;
      },
      importIdentity: (blob) => {
        get().unlocked?.lock();
        set({ identity: blob, unlocked: undefined });
      },
      clearIdentity: () => {
        get().unlocked?.lock();
        set({ identity: undefined, unlocked: undefined });
      },
      unlock: async (passphrase) => {
        const id = get().identity;
        if (!id) throw new Error("No identity on this desk — create one first.");
        const u = await unlockKs(id, passphrase); // uniform error on wrong passphrase
        get().unlocked?.lock();
        set({ unlocked: u });
      },
      lock: () => {
        get().unlocked?.lock();
        set({ unlocked: undefined });
      },
      persistKeystore: (blob) => set({ identity: blob }),
      addPrekeys: (n) => {
        const u = get().unlocked;
        if (!u) throw new Error("Unlock your identity first.");
        const { keystore, prekeys } = u.addPrekeys(n);
        set({ identity: keystore });
        return prekeys;
      },
      setTrust: (anchor, at) => {
        const when = at ?? new Date();
        if (!verifyDirectory(anchor.directory, anchor.rootPublicKeyHex, when)) {
          throw new Error("Directory does not verify against this root public key.");
        }
        // Keep only bundles that verify against the same root (fail closed).
        const bundles: Record<string, PrekeyBundle> = {};
        for (const [org, b] of Object.entries(anchor.bundles ?? {})) {
          if (verifyPrekeyBundle(b, anchor.directory, anchor.rootPublicKeyHex, when)) bundles[org] = b;
        }
        set({ trust: { rootPublicKeyHex: anchor.rootPublicKeyHex, directory: anchor.directory, bundles } });
      },
      clearTrust: () => set({ trust: undefined }),
    }),
    {
      name: "sje-keys-001",
      skipHydration: true,
      storage: createJSONStorage(() => safeStorage),
      // Persist ONLY the encrypted blob and the public trust anchor — never the
      // unlocked session (it holds the plaintext secret and live functions).
      partialize: (s) => ({ identity: s.identity, trust: s.trust }),
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<KeysState>;
        return { ...current, identity: p.identity, trust: p.trust, unlocked: undefined, hydrated: false };
      },
    },
  ),
);
