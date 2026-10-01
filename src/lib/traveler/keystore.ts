/** Passphrase-encrypted key store — custody for the secret keys the encrypted
 *  transport needs to OPEN envelopes.
 *
 *  Sealing (encrypting TO a recipient) needs only a public key, so it needs no
 *  keystore. OPENING needs the recipient's ML-KEM secret, and that secret must not
 *  sit in plaintext localStorage. This vault holds the org's secret key material
 *  encrypted at rest under a key derived from a passphrase (scrypt) with
 *  AES-256-GCM; the plaintext secret exists only in memory, only while unlocked.
 *
 *  What's stored: SEEDS, not expanded keys — the 64-byte ML-KEM identity seed, an
 *  optional ML-DSA signing seed (populated only by a server/CLI that signs prekey
 *  bundles; the browser desk never sets it, preserving "the desk holds no signing
 *  keys"), and a map of one-time prekey_id -> seed for forward secrecy. On unlock
 *  the public key is re-derived and checked against the stored clear public key, so
 *  a tampered header cannot point the vault at a substituted identity.
 *
 *  THREAT MODEL (honest): the at-rest encryption protects a stolen keystore blob
 *  (disk / localStorage) WITHOUT the passphrase — at-rest safety is passphrase
 *  entropy x scrypt cost, so a weak passphrase plus a stolen blob is crackable
 *  offline. It does NOT protect against script running in the origin: an XSS on an
 *  UNLOCKED desk can read the in-memory secret (ML-KEM runs in JS; the key is
 *  extractable during decapsulation). Lock promptly; keep unlocked lifetime short.
 *
 *  The keystore is LOCAL custody and never travels on the wire, so it is
 *  TypeScript-only — there is no cross-implementation vector for it (unlike the
 *  envelope it guards, which is dual-language and vectored).
 */
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "./bytes.ts";
import { canonicalJson } from "./canonical.ts";
import { KEM_ALG, encKid, kemKeypairFromSeed } from "./envelope.ts";

export const KEYSTORE_SPEC = "sje-keystore/0.1.0" as const;

// scrypt N=2^16 (~64 MiB, ~0.3-1s in pure-JS behind an explicit unlock). Stored in
// the blob for agility; unlock upgrades a blob below the floor. p stays 1 (noble's
// p is sequential in JS — raising it only adds latency, no parallel speedup).
const SCRYPT_N = 65536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32;
const MIN_SCRYPT_N = 32768; // floor; below this, re-wrap on unlock
const MIN_PASSPHRASE = 12; // characters
const KEM_SEED_LEN = 64;
const SALT_LEN = 16;
const NONCE_LEN = 12;

const UNLOCK_FAIL = "keystore unlock failed (wrong passphrase or corrupt keystore)";

type Kdf = { name: "scrypt"; N: number; r: number; p: number; salt: string };

/** The persisted blob. Header fields are clear; `ct` is the AES-256-GCM-encrypted
 *  vault. Safe to store in localStorage or a file. */
export type Keystore = {
  spec: typeof KEYSTORE_SPEC;
  kid: string; // encKid(enc_public_key) — equals the envelope recipient kid
  enc_alg: typeof KEM_ALG;
  enc_public_key: string; // hex ML-KEM-1024 public key (clear)
  org_id?: string; // UX label only (clear)
  kdf: Kdf;
  cipher: "AES-256-GCM";
  nonce: string; // hex
  ct: string; // hex (encrypted vault + GCM tag)
};

/** Decrypted contents — never persisted in the clear. */
type Vault = {
  static_seed: string; // hex 64-byte ML-KEM seed
  sign_seed?: string; // hex ML-DSA seed (server/CLI only)
  prekeys: Record<string, string>; // prekey_id -> hex 64-byte ML-KEM seed
};

export type PublicPrekey = { prekey_id: string; public_key: string };
export type DirectoryEntryPublic = {
  org_id?: string;
  enc_alg: typeof KEM_ALG;
  enc_public_key: string;
  kid: string;
};

function randomBytes(n: number): Uint8Array {
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    // No insecure fallback: key material must come from a CSPRNG (ids.ts rule).
    throw new Error("a secure random source (crypto.getRandomValues) is required");
  }
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function assertPassphrase(p: string): void {
  if (typeof p !== "string" || p.length < MIN_PASSPHRASE) {
    throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  }
}

/** AAD binds the clear header (identity + KDF params) to the ciphertext, so a
 *  tampered header fails the GCM tag with the same uniform error as a wrong
 *  passphrase — no distinguishing oracle. */
function aad(header: Pick<Keystore, "kid" | "enc_alg" | "enc_public_key" | "kdf">): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      spec: KEYSTORE_SPEC,
      kid: header.kid,
      enc_alg: header.enc_alg,
      enc_public_key: header.enc_public_key,
      kdf: header.kdf,
    }),
  );
}

async function deriveKey(passphrase: string, kdf: Kdf): Promise<Uint8Array> {
  return scryptAsync(utf8ToBytes(passphrase), hexToBytes(kdf.salt), {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    dkLen: SCRYPT_DKLEN,
  });
}

function sealVault(vault: Vault, key: Uint8Array, header: Keystore): { nonce: string; ct: string } {
  const nonce = randomBytes(NONCE_LEN);
  const ct = gcm(key, nonce, aad(header)).encrypt(utf8ToBytes(JSON.stringify(vault)));
  return { nonce: bytesToHex(nonce), ct: bytesToHex(ct) };
}

/** Create a fresh ML-KEM identity and return the encrypted keystore plus the public
 *  directory-entry fields to publish. `signSeed` is optional and server-only; the
 *  browser desk omits it. */
export async function createIdentity(opts: {
  passphrase: string;
  orgId?: string;
  signSeed?: Uint8Array;
}): Promise<{ keystore: Keystore; directoryEntry: DirectoryEntryPublic }> {
  assertPassphrase(opts.passphrase);
  const seed = randomBytes(KEM_SEED_LEN);
  const kp = kemKeypairFromSeed(seed);
  const enc_public_key = bytesToHex(kp.publicKey);
  const kid = encKid(enc_public_key);
  const kdf: Kdf = { name: "scrypt", N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt: bytesToHex(randomBytes(SALT_LEN)) };
  const header: Keystore = {
    spec: KEYSTORE_SPEC,
    kid,
    enc_alg: KEM_ALG,
    enc_public_key,
    ...(opts.orgId ? { org_id: opts.orgId } : {}),
    kdf,
    cipher: "AES-256-GCM",
    nonce: "",
    ct: "",
  };
  const vault: Vault = {
    static_seed: bytesToHex(seed),
    ...(opts.signSeed ? { sign_seed: bytesToHex(opts.signSeed) } : {}),
    prekeys: {},
  };
  const key = await deriveKey(opts.passphrase, kdf);
  const { nonce, ct } = sealVault(vault, key, header);
  return {
    keystore: { ...header, nonce, ct },
    directoryEntry: { ...(opts.orgId ? { org_id: opts.orgId } : {}), enc_alg: KEM_ALG, enc_public_key, kid },
  };
}

/** A live, unlocked keystore. Holds the derived key and vault in memory (this is
 *  the "plaintext secret while unlocked" of the threat model). Mutating operations
 *  return a new encrypted blob to persist. */
export type Unlocked = {
  readonly kid: string;
  readonly encPublicKeyHex: string;
  readonly orgId?: string;
  /** The ML-KEM identity secret key (for openEnvelope / the static half of FS). */
  staticSecretKey(): Uint8Array;
  /** The ML-DSA signing seed, if this keystore carries one (server/CLI only). */
  signSeed(): Uint8Array | undefined;
  /** Generate n one-time prekeys; stores their secrets, returns the public list to
   *  publish in a signed bundle, and the new keystore blob to persist. */
  addPrekeys(n: number): { keystore: Keystore; prekeys: PublicPrekey[] };
  /** Look up a one-time prekey secret and DELETE it (forward secrecy). Returns the
   *  secret (or undefined if already consumed/unknown) and the new blob to persist
   *  BEFORE the secret is used, so a crash can't resurrect a consumed prekey. */
  consumePrekey(prekeyId: string): { keystore: Keystore; secretKey: Uint8Array | undefined };
  /** Best-effort wipe of in-memory key material; the keystore becomes unusable. */
  lock(): void;
};

/** Unlock a keystore blob. Throws the uniform UNLOCK_FAIL on a wrong passphrase, a
 *  tampered blob, or a header that does not match the sealed identity. */
export async function unlock(store: Keystore, passphrase: string): Promise<Unlocked> {
  if (store.spec !== KEYSTORE_SPEC || store.cipher !== "AES-256-GCM" || store.kdf?.name !== "scrypt") {
    throw new Error(UNLOCK_FAIL);
  }
  const key = await deriveKey(passphrase, store.kdf);
  let vault: Vault;
  try {
    const pt = gcm(key, hexToBytes(store.nonce), aad(store)).decrypt(hexToBytes(store.ct));
    vault = JSON.parse(new TextDecoder().decode(pt)) as Vault;
  } catch {
    throw new Error(UNLOCK_FAIL);
  }
  if (typeof vault?.static_seed !== "string" || typeof vault.prekeys !== "object" || vault.prekeys === null) {
    throw new Error(UNLOCK_FAIL);
  }

  // Substitution check: the sealed seed must derive exactly the clear public key /
  // kid in the header. Otherwise a tampered header could point at another identity.
  const kp = kemKeypairFromSeed(hexToBytes(vault.static_seed));
  const derivedPub = bytesToHex(kp.publicKey);
  if (derivedPub !== store.enc_public_key || encKid(derivedPub) !== store.kid) {
    throw new Error(UNLOCK_FAIL);
  }

  // Header carried forward for re-sealing (upgrade N if below the floor).
  const kdf: Kdf =
    store.kdf.N < MIN_SCRYPT_N
      ? { name: "scrypt", N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt: store.kdf.salt }
      : store.kdf;
  const header: Keystore = { ...store, kdf };
  let activeKey = key;
  let locked = false;

  const requireOpen = () => {
    if (locked) throw new Error("keystore is locked");
  };
  const reseal = (): Keystore => {
    const { nonce, ct } = sealVault(vault, activeKey, header);
    return { ...header, nonce, ct };
  };

  return {
    kid: store.kid,
    encPublicKeyHex: store.enc_public_key,
    orgId: store.org_id,
    staticSecretKey() {
      requireOpen();
      return kemKeypairFromSeed(hexToBytes(vault.static_seed)).secretKey;
    },
    signSeed() {
      requireOpen();
      return vault.sign_seed ? hexToBytes(vault.sign_seed) : undefined;
    },
    addPrekeys(n: number) {
      requireOpen();
      if (!Number.isInteger(n) || n < 1 || n > 1024) throw new Error("prekey count must be 1..1024");
      const prekeys: PublicPrekey[] = [];
      for (let i = 0; i < n; i++) {
        const seed = randomBytes(KEM_SEED_LEN);
        const pub = bytesToHex(kemKeypairFromSeed(seed).publicKey);
        const prekey_id = encKid(pub); // binds id to key
        vault.prekeys[prekey_id] = bytesToHex(seed);
        prekeys.push({ prekey_id, public_key: pub });
      }
      return { keystore: reseal(), prekeys };
    },
    consumePrekey(prekeyId: string) {
      requireOpen();
      const seedHex = vault.prekeys[prekeyId];
      if (!seedHex) return { keystore: reseal(), secretKey: undefined };
      const secretKey = kemKeypairFromSeed(hexToBytes(seedHex)).secretKey;
      delete vault.prekeys[prekeyId];
      return { keystore: reseal(), secretKey };
    },
    lock() {
      locked = true;
      activeKey.fill(0); // best-effort; hex strings in `vault` are immutable and linger until GC
      activeKey = new Uint8Array(0);
      vault = { static_seed: "", prekeys: {} };
    },
  };
}
