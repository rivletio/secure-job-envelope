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
 *  keys"), and a map of one-time prekey_id -> seed for forward secrecy.
 *
 *  THE BLOB IS UNTRUSTED INPUT. It sits in localStorage or a file, where anything
 *  that can write there can rewrite it, and it is read before any secret is known.
 *  So:
 *
 *    - Its whole shape is checked BEFORE the key-derivation function runs
 *      (`keystoreShapeError`): exact member set, types, exact salt / nonce / key
 *      lengths, and — above all — the scrypt cost, which the blob itself declares.
 *      Unbounded, a hostile blob made unlock run for hours or allocate until the
 *      process died (N, r and p were passed straight to scrypt), and a blob at
 *      N = 2 unlocked as if it were protected. The cost must now be a power of two
 *      in [2^15, 2^20] with r = 8 and p = 1 — every keystore this code has ever
 *      written is N = 2^16, r = 8, p = 1.
 *    - Every way of not unlocking — wrong passphrase, tampered blob, refused
 *      parameters, a blob that is not a keystore at all — is ONE error, so the
 *      error says nothing about which it was.
 *    - The clear header is authenticated. In `sje-keystore/0.2.0` the AEAD's
 *      associated data is the entire header (below), so editing any clear member
 *      of the blob makes it fail to unlock. `sje-keystore/0.1.0` bound everything
 *      except `org_id`, which could be rewritten freely; 0.1.0 blobs are still
 *      read (nobody is locked out) and are written back as 0.2.0 the next time
 *      they are re-sealed.
 *
 *  Authenticated means "when unlocked": a locked blob's header is only a claim.
 *  Read identity from the `Unlocked` session, not from the blob.
 *
 *  FORMAT (a local at-rest format; it never travels, so it is TypeScript-only and
 *  has no cross-implementation vector):
 *
 *    { spec, kid, enc_alg, enc_public_key, org_id?, kdf: { name, N, r, p, salt },
 *      cipher, nonce, ct }
 *
 *    key   = scrypt(passphrase, salt, N, r, p, dkLen 32)
 *    ct    = AES-256-GCM(key, nonce, aad).encrypt(UTF-8 JSON of the vault)
 *    aad   = UTF-8 canonical JSON of, for
 *      0.2.0: { spec, kid, enc_alg, enc_public_key, org_id (or null), kdf, cipher }
 *             — every member of the blob except `nonce` and `ct`, which the AEAD
 *             authenticates by construction
 *      0.1.0: { spec, kid, enc_alg, enc_public_key, kdf }
 *    The version string is inside both, so a blob cannot be relabelled from one
 *    version to the other.
 *
 *  THREAT MODEL (honest): the at-rest encryption protects a stolen keystore blob
 *  (disk / localStorage) WITHOUT the passphrase — at-rest safety is passphrase
 *  entropy x scrypt cost, so a weak passphrase plus a stolen blob is crackable
 *  offline. It does NOT protect against script running in the origin: an XSS on an
 *  UNLOCKED desk can read the in-memory secret (ML-KEM runs in JS; the key is
 *  extractable during decapsulation). Lock promptly; keep unlocked lifetime short.
 *  And the blob carries no counter: whoever can write it can put an OLDER blob
 *  back (a consumed one-time prekey returns with it). Nothing here detects that.
 */
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from "./bytes.ts";
import { LONE_SURROGATE, canonicalJson } from "./canonical.ts";
import { ML_KEM_1024_PUBLIC_KEY_BYTES, hasMembers, isHexOf } from "./directory.ts";
import { KEM_ALG, encKid, kemKeypairFromSeed } from "./envelope.ts";

/** The format this version writes. */
export const KEYSTORE_SPEC = "sje-keystore/0.2.0" as const;
/** The first format: still read, never written. Its AAD did not cover `org_id`. */
export const KEYSTORE_SPEC_LEGACY = "sje-keystore/0.1.0" as const;

const CIPHER = "AES-256-GCM" as const;

// scrypt N=2^16 (~64 MiB, ~0.3-1s in pure JS behind an explicit unlock). The
// parameters are stored in the blob for agility, which makes them attacker-supplied:
// a blob may only ask for a cost inside the bounds below. Memory is 128·N·r bytes, so
// r = 8 gives 32 MiB at the floor and 1 GiB at the ceiling; p stays 1 (noble's p is
// sequential in JS — raising it only multiplies the time).
const SCRYPT_N = 65536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32;
/** The least and greatest scrypt N a blob may declare (powers of two only). */
export const MIN_SCRYPT_N = 32768; // 2^15
export const MAX_SCRYPT_N = 1048576; // 2^20
const MIN_PASSPHRASE = 12; // characters
const KEM_SEED_LEN = 64;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const GCM_TAG_LEN = 16;
/** `org_id` in a keystore is a label its owner typed; bounded, not interpreted. */
const MAX_ORG_LABEL = 256;
/** Most encrypted-vault bytes a blob may carry (a vault is ~150 bytes per prekey). */
const MAX_VAULT_CT_BYTES = 8 * 1024 * 1024;

const UNLOCK_FAIL = "keystore unlock failed (wrong passphrase or corrupt keystore)";

type Kdf = { name: "scrypt"; N: number; r: number; p: number; salt: string };

/** The persisted blob. Header fields are clear; `ct` is the AES-256-GCM-encrypted
 *  vault. Safe to store in localStorage or a file. */
export type Keystore = {
  spec: typeof KEYSTORE_SPEC | typeof KEYSTORE_SPEC_LEGACY;
  kid: string; // encKid(enc_public_key) — equals the envelope recipient kid
  enc_alg: typeof KEM_ALG;
  enc_public_key: string; // hex ML-KEM-1024 public key (clear)
  org_id?: string; // UX label only (clear)
  kdf: Kdf;
  cipher: typeof CIPHER;
  nonce: string; // hex
  ct: string; // hex (encrypted vault + GCM tag)
};

/** The clear header: the blob without the two members the AEAD authenticates itself. */
type KeystoreHeader = Omit<Keystore, "nonce" | "ct">;

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

function assertPassphrase(p: string): void {
  if (typeof p !== "string" || p.length < MIN_PASSPHRASE) {
    throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  }
}

function orgLabelOk(v: unknown): v is string {
  return typeof v === "string" && v.length >= 1 && v.length <= MAX_ORG_LABEL && !LONE_SURROGATE.test(v);
}

function kdfShapeError(kdf: unknown): string | null {
  if (!hasMembers(kdf, ["name", "N", "r", "p", "salt"])) return "kdf has unexpected or missing members";
  if (kdf.name !== "scrypt") return "kdf.name";
  const N = kdf.N;
  if (
    typeof N !== "number" ||
    !Number.isInteger(N) ||
    N < MIN_SCRYPT_N ||
    N > MAX_SCRYPT_N ||
    (N & (N - 1)) !== 0
  ) {
    return "kdf.N";
  }
  if (kdf.r !== SCRYPT_R) return "kdf.r";
  if (kdf.p !== SCRYPT_P) return "kdf.p";
  if (!isHexOf(kdf.salt, SALT_LEN)) return "kdf.salt";
  return null;
}

/** Why `blob` is not a well-formed keystore, or null if it is. Uses no secret and runs
 *  no key derivation, so it is safe on anything — and `unlock` runs it first, before
 *  the blob's own cost parameters are allowed to cost anything.
 *
 *    blob   exactly { spec, kid, enc_alg, enc_public_key, kdf, cipher, nonce, ct },
 *           optionally { org_id }; nothing else
 *    spec   "sje-keystore/0.2.0", or the legacy "sje-keystore/0.1.0"
 *    key    enc_alg "ML-KEM-1024"; enc_public_key 1568 bytes of lowercase hex;
 *           kid = encKid(enc_public_key)
 *    org_id a string of 1–256 characters (a label; not interpreted)
 *    kdf    exactly { name: "scrypt", N, r, p, salt }: N a power of two in
 *           [2^15, 2^20], r = 8, p = 1, salt 16 bytes of lowercase hex
 *    cipher "AES-256-GCM"; nonce 12 bytes of lowercase hex; ct lowercase hex, longer
 *           than a bare GCM tag, at most 8 MiB
 *
 *  The reason is for the keystore's OWNER (a settings page, a log). `unlock` never
 *  reports it: there, every failure is the same error. */
export function keystoreShapeError(blob: unknown): string | null {
  if (
    !hasMembers(
      blob,
      ["spec", "kid", "enc_alg", "enc_public_key", "kdf", "cipher", "nonce", "ct"],
      ["org_id"],
    )
  ) {
    return "unexpected or missing members";
  }
  if (blob.spec !== KEYSTORE_SPEC && blob.spec !== KEYSTORE_SPEC_LEGACY) return "unsupported spec";
  if (blob.enc_alg !== KEM_ALG) return "enc_alg";
  if (!isHexOf(blob.enc_public_key, ML_KEM_1024_PUBLIC_KEY_BYTES)) return "enc_public_key";
  if (blob.kid !== encKid(blob.enc_public_key)) return "kid";
  if (Object.hasOwn(blob, "org_id") && !orgLabelOk(blob.org_id)) return "org_id";
  const kdf = kdfShapeError(blob.kdf);
  if (kdf !== null) return kdf;
  if (blob.cipher !== CIPHER) return "cipher";
  if (!isHexOf(blob.nonce, NONCE_LEN)) return "nonce";
  const ct = blob.ct;
  if (
    typeof ct !== "string" ||
    ct.length % 2 !== 0 ||
    ct.length <= 2 * GCM_TAG_LEN ||
    ct.length > 2 * MAX_VAULT_CT_BYTES ||
    !/^[0-9a-f]+$/.test(ct)
  ) {
    return "ct";
  }
  return null;
}

/** Associated data of the CURRENT format: the whole clear header. Any edit to a clear
 *  member — the org label included — changes these bytes, so the GCM tag fails with
 *  the same uniform error as a wrong passphrase. `org_id` is always present here
 *  (null when the blob has none), so "no label" and "a label" cannot be confused. */
function aadCurrent(h: KeystoreHeader): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      spec: KEYSTORE_SPEC,
      kid: h.kid,
      enc_alg: h.enc_alg,
      enc_public_key: h.enc_public_key,
      org_id: h.org_id ?? null,
      kdf: h.kdf,
      cipher: h.cipher,
    }),
  );
}

/** Associated data of the legacy format — exactly what 0.1.0 wrote, so 0.1.0 blobs
 *  still open. It does not cover `org_id` (nor `cipher`, which has one legal value). */
function aadLegacy(h: KeystoreHeader): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      spec: KEYSTORE_SPEC_LEGACY,
      kid: h.kid,
      enc_alg: h.enc_alg,
      enc_public_key: h.enc_public_key,
      kdf: h.kdf,
    }),
  );
}

/** Only ever called with a `kdf` that passed `kdfShapeError`. */
async function deriveKey(passphrase: string, kdf: Kdf): Promise<Uint8Array> {
  return scryptAsync(utf8ToBytes(passphrase), hexToBytes(kdf.salt), {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    dkLen: SCRYPT_DKLEN,
  });
}

function freshKdf(): Kdf {
  return { name: "scrypt", N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt: bytesToHex(randomBytes(SALT_LEN)) };
}

/** Seal `vault` under `header` (always the current format) with a fresh nonce. */
function sealVault(vault: Vault, key: Uint8Array, header: KeystoreHeader): Keystore {
  const nonce = randomBytes(NONCE_LEN);
  const ct = gcm(key, nonce, aadCurrent(header)).encrypt(utf8ToBytes(JSON.stringify(vault)));
  return { ...header, nonce: bytesToHex(nonce), ct: bytesToHex(ct) };
}

/** Parse decrypted vault bytes, or throw. The vault was written by whoever holds the
 *  passphrase, so this is a sanity check on our own format, not a trust boundary. */
function parseVault(pt: Uint8Array): Vault {
  const v: unknown = JSON.parse(new TextDecoder().decode(pt));
  if (!hasMembers(v, ["static_seed", "prekeys"], ["sign_seed"])) throw new Error("vault shape");
  if (!isHexOf(v.static_seed, KEM_SEED_LEN)) throw new Error("vault static_seed");
  if (Object.hasOwn(v, "sign_seed")) {
    const s = v.sign_seed;
    if (typeof s !== "string" || s.length === 0 || s.length % 2 !== 0 || !/^[0-9a-f]+$/.test(s)) {
      throw new Error("vault sign_seed");
    }
  }
  const prekeys = v.prekeys;
  if (prekeys === null || typeof prekeys !== "object" || Array.isArray(prekeys)) {
    throw new Error("vault prekeys");
  }
  return v as Vault;
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
  if (opts.orgId && !orgLabelOk(opts.orgId)) {
    throw new Error(`org id label must be 1–${MAX_ORG_LABEL} characters`);
  }
  const seed = randomBytes(KEM_SEED_LEN);
  const kp = kemKeypairFromSeed(seed);
  const enc_public_key = bytesToHex(kp.publicKey);
  const kid = encKid(enc_public_key);
  const kdf = freshKdf();
  const header: KeystoreHeader = {
    spec: KEYSTORE_SPEC,
    kid,
    enc_alg: KEM_ALG,
    enc_public_key,
    ...(opts.orgId ? { org_id: opts.orgId } : {}),
    kdf,
    cipher: CIPHER,
  };
  const vault: Vault = {
    static_seed: bytesToHex(seed),
    ...(opts.signSeed ? { sign_seed: bytesToHex(opts.signSeed) } : {}),
    prekeys: {},
  };
  const key = await deriveKey(opts.passphrase, kdf);
  return {
    keystore: sealVault(vault, key, header),
    directoryEntry: { ...(opts.orgId ? { org_id: opts.orgId } : {}), enc_alg: KEM_ALG, enc_public_key, kid },
  };
}

/** A live, unlocked keystore. Holds the derived key and vault in memory (this is
 *  the "plaintext secret while unlocked" of the threat model). Mutating operations
 *  return a new encrypted blob to persist — always in the current format. */
export type Unlocked = {
  readonly kid: string;
  readonly encPublicKeyHex: string;
  /** The org label from the header. Authenticated when the blob was in the current
   *  format; a legacy (0.1.0) blob did not bind it, so until that blob has been
   *  re-sealed this is only what the stored blob said. */
  readonly orgId?: string;
  /** True iff the blob this was unlocked from is not what this version would write —
   *  the legacy format, or a KDF cost below this version's. `reseal()` (and every
   *  mutating operation) returns the upgraded blob; persist it. */
  readonly needsUpgrade: boolean;
  /** The ML-KEM identity secret key (for openEnvelope / the static half of FS). */
  staticSecretKey(): Uint8Array;
  /** The ML-DSA signing seed, if this keystore carries one (server/CLI only). */
  signSeed(): Uint8Array | undefined;
  /** Re-seal the vault as it stands — current format, fresh nonce — and return the
   *  blob to persist. Changes no key material. */
  reseal(): Keystore;
  /** Generate n one-time prekeys; stores their secrets, returns the public list to
   *  publish in a signed bundle, and the new keystore blob to persist. */
  addPrekeys(n: number): { keystore: Keystore; prekeys: PublicPrekey[] };
  /** How many one-time prekeys this keystore holds (unspent). */
  prekeyCount(): number;
  /** Look up a one-time prekey secret WITHOUT consuming it, so a caller can verify an
   *  envelope actually opens before committing the single-use deletion — so an envelope
   *  that FAILS AEAD cannot burn a prekey. (A party holding the public bundle can still
   *  burn prekeys with a validly-encrypted junk envelope; one-time pools are inherently
   *  exhaustible — see transport.ts.) Returns undefined if the id is unknown or already
   *  consumed. */
  peekPrekey(prekeyId: string): Uint8Array | undefined;
  /** Delete a one-time prekey and return the new blob to persist (forward secrecy).
   *  Call this only AFTER the envelope has been verified to open (see peekPrekey), so a
   *  forgery that FAILS AEAD cannot burn it; persist the returned blob before releasing
   *  the plaintext. (A validly-encrypted junk envelope from anyone holding the public
   *  bundle can still consume a prekey — pool exhaustion is expected, not prevented.)
   *  The deletion is real only once the returned blob has REPLACED the stored one: until
   *  then the secret is still on disk, and a second session unlocked from the same
   *  stored blob still holds it. */
  consumePrekey(prekeyId: string): { keystore: Keystore; secretKey: Uint8Array | undefined };
  /** The blob this keystore WOULD become with one-time prekey `prekeyId` deleted —
   *  without deleting it here. For a caller that has to store a deletion before it takes
   *  effect in this session: write the returned blob, and only once that has succeeded
   *  call `consumePrekey`. Done the other way round, a write that fails leaves this
   *  session without a prekey the stored blob still has. An id that is not held gives
   *  the vault as it stands. */
  withoutPrekey(prekeyId: string): Keystore;
  /** Best-effort wipe of in-memory key material; the keystore becomes unusable. */
  lock(): void;
};

/** Unlock a keystore blob.
 *
 *  Throws the SAME error — nothing else, and nothing more specific — for a wrong
 *  passphrase, a tampered blob, a header that does not match the sealed identity, cost
 *  parameters outside the accepted bounds, or a value that is not a keystore at all.
 *  (A refused blob fails at once and a wrong passphrase fails after the derivation, so
 *  timing still tells them apart; that is not a secret — the blob's shape is checked
 *  without the passphrase and says nothing about it.) */
export async function unlock(store: Keystore, passphrase: string): Promise<Unlocked> {
  // The blob is untrusted: its shape — including the cost it asks for — is checked
  // before it is allowed to cost anything.
  if (typeof passphrase !== "string" || keystoreShapeError(store) !== null) {
    throw new Error(UNLOCK_FAIL);
  }
  // Work from a snapshot, so what was checked is what is used.
  const legacy = store.spec === KEYSTORE_SPEC_LEGACY;
  const stored: KeystoreHeader = {
    spec: store.spec,
    kid: store.kid,
    enc_alg: KEM_ALG,
    enc_public_key: store.enc_public_key,
    ...(store.org_id !== undefined ? { org_id: store.org_id } : {}),
    kdf: { name: "scrypt", N: store.kdf.N, r: store.kdf.r, p: store.kdf.p, salt: store.kdf.salt },
    cipher: CIPHER,
  };
  const nonce = store.nonce;
  const ct = store.ct;

  let vault: Vault;
  let activeKey: Uint8Array;
  let kdf: Kdf = stored.kdf;
  try {
    const key = await deriveKey(passphrase, stored.kdf);
    const aad = legacy ? aadLegacy(stored) : aadCurrent(stored);
    vault = parseVault(gcm(key, hexToBytes(nonce), aad).decrypt(hexToBytes(ct)));

    // Substitution check: the sealed seed must derive exactly the clear public key in
    // the header (the kid was already checked against that key). Otherwise a header
    // could point at another identity.
    const derivedPub = bytesToHex(kemKeypairFromSeed(hexToBytes(vault.static_seed)).publicKey);
    if (derivedPub !== stored.enc_public_key) throw new Error("identity mismatch");

    // If the stored cost is below what this version writes, upgrade the KDF *and
    // re-derive the key under the new params* (with a fresh salt), so the resealed
    // blob is encrypted with the key its own header advertises. (An earlier version
    // upgraded the header but reused the old key to reseal, so the next unlock derived
    // a different key and the keystore was bricked forever.)
    activeKey = key;
    if (stored.kdf.N < SCRYPT_N) {
      kdf = freshKdf();
      activeKey = await deriveKey(passphrase, kdf);
      key.fill(0);
    }
  } catch {
    throw new Error(UNLOCK_FAIL);
  }

  // The header every re-seal writes: the same identity, in the current format.
  const header: KeystoreHeader = { ...stored, spec: KEYSTORE_SPEC, kdf };
  const needsUpgrade = legacy || kdf !== stored.kdf;
  let locked = false;

  const requireOpen = () => {
    if (locked) throw new Error("keystore is locked");
  };
  const reseal = (): Keystore => sealVault(vault, activeKey, header);
  // Own-property lookup only: an attacker-chosen id like "__proto__" or "toString"
  // must not resolve to an inherited Object.prototype member.
  const prekeySeed = (prekeyId: string): string | undefined => {
    const seedHex = Object.hasOwn(vault.prekeys, prekeyId) ? vault.prekeys[prekeyId] : undefined;
    return isHexOf(seedHex, KEM_SEED_LEN) ? seedHex : undefined;
  };

  return {
    kid: stored.kid,
    encPublicKeyHex: stored.enc_public_key,
    orgId: stored.org_id,
    needsUpgrade,
    staticSecretKey() {
      requireOpen();
      return kemKeypairFromSeed(hexToBytes(vault.static_seed)).secretKey;
    },
    signSeed() {
      requireOpen();
      return vault.sign_seed ? hexToBytes(vault.sign_seed) : undefined;
    },
    reseal() {
      requireOpen();
      return reseal();
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
    prekeyCount() {
      requireOpen();
      return Object.keys(vault.prekeys).length;
    },
    peekPrekey(prekeyId: string) {
      requireOpen();
      const seedHex = prekeySeed(prekeyId);
      return seedHex === undefined ? undefined : kemKeypairFromSeed(hexToBytes(seedHex)).secretKey;
    },
    consumePrekey(prekeyId: string) {
      requireOpen();
      const seedHex = prekeySeed(prekeyId);
      if (seedHex === undefined) return { keystore: reseal(), secretKey: undefined };
      const secretKey = kemKeypairFromSeed(hexToBytes(seedHex)).secretKey;
      delete vault.prekeys[prekeyId];
      return { keystore: reseal(), secretKey };
    },
    withoutPrekey(prekeyId: string) {
      requireOpen();
      if (prekeySeed(prekeyId) === undefined) return reseal();
      const prekeys = Object.fromEntries(Object.entries(vault.prekeys).filter(([id]) => id !== prekeyId));
      return sealVault({ ...vault, prekeys }, activeKey, header);
    },
    lock() {
      locked = true;
      activeKey.fill(0); // best-effort; hex strings in `vault` are immutable and linger until GC
      activeKey = new Uint8Array(0);
      vault = { static_seed: "", prekeys: {} };
    },
  };
}
