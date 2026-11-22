# Encrypted envelope (`.sje`)

**Status: IMPLEMENTED.** The base envelope (`sje-envelope/0.1.0`) selects its
algorithms from the CNSA 2.0 Category 5 suite — ML-KEM-1024 + HKDF-SHA-384 +
AES-256-GCM (this draft's earlier ML-KEM-768 default was promoted to 1024).
**Forward secrecy is implemented too**, as a coexisting `sje-envelope/0.2.0`
mode that adds single-use prekeys and a two-KEM combine (see
[Forward secrecy](#forward-secrecy-sje-envelope020) below). Both are proven by
dual-language golden vectors — see `docs/CLAIMS.md` PQ4 / PQ7–PQ9,
`src/lib/traveler/envelope.ts`, and `crates/secure-job-envelope/src/envelope.rs`.
Selecting NIST / CNSA 2.0 algorithms is an engineering choice, not a
certification (see the README Disclaimer).

The envelope is now the **default transport**, not just a library primitive:
`src/lib/traveler/transport.ts` seals a traveler into it and opens it with a
passphrase-encrypted keystore (`keystore.ts`), and both the MCP tools and the
browser desk send the `.sje` rather than a plaintext zip (see `docs/CLAIMS.md`
KS1 / T1–T5).

File extension `.sje`. Goal: a traveler exchanged between two shops is
confidential against an adversary who records everything today and owns a
cryptographically relevant quantum computer later.

## Why this exists

A protocol that aims to carry manufacturing coordination at national scale
carries two kinds of secrets:

1. **Payload secrets** — pricing, lead times, process notes, drawings.
   Trade secrets do not expire like credit cards; a quote captured in
   transit today must still be confidential in 2045. Classical TLS key
   exchange (ECDH) does not survive *harvest-now-decrypt-later*; this
   envelope must.
2. **Flow secrets** — the graph of who is quoting whom, for what part
   families, at what cadence. In aggregate this is a map of the industrial
   base. The envelope alone cannot hide traffic flows from the transport,
   but it must not *add* metadata: no org names, no part numbers, no
   traveler ids in the clear.

Design consequence of the second point: SJE remains a **file
format, not a platform** — there is deliberately no central broker that
sees plaintext or the full exchange graph. Anyone who builds a relay or
directory on top of this spec should treat that property as normative.

## Algorithm suite (CNSA 2.0 suite)

All primitives are NIST-standardized and drawn from the CNSA 2.0 Category 5
suite, so the same envelope can be used by commercial shops and by
defense-industrial-base suppliers — subject to those parties' own control
environments and obligations:

| Purpose | Algorithm | Note |
|---|---|---|
| Key establishment | **ML-KEM-1024** (FIPS 203) | one encapsulation per recipient (0.1); two per recipient in the forward-secret 0.2 mode (one-time prekey + static) |
| Payload encryption | **AES-256-GCM** | 256-bit key; Grover-adjusted margin ~128-bit |
| KDF | **HKDF-SHA-384** | matches the format's hash family |
| Content addressing | **SHA-384** | unchanged from the base spec |
| Party authentication | **ML-DSA-87** (FIPS 204) | authorship signatures on the traveler/quote, verified against the signed directory (implemented; CLAIMS PQ1–PQ6). SLH-DSA (FIPS 205) is a roadmap alternative |

No classical-only key exchange is permitted in any profile. The forward-secret
mode binds two ML-KEM shared secrets into the KEK; any future hybrid MUST
likewise bind all shared secrets.

## Envelope shape (0.1, static keys)

A `.sje` is a JSON document (same ethos as the traveler — inspectable structure,
opaque payload). Byte fields are lowercase hex.

```jsonc
{
  "spec": "sje-envelope/0.1.0",
  "enc_alg": "ML-KEM-1024+HKDF-SHA-384+AES-256-GCM",
  "payload_nonce": "hex(96-bit)",
  "payload": "hex(AES-256-GCM(CEK, payload) incl tag)",
  "recipients": [
    {
      "kid": "hex(SHA-384(recipient ML-KEM public key))[0..16]",
      "kem_ct": "hex(ML-KEM ciphertext)",
      "wrap_nonce": "hex(96-bit)",
      "wrapped_cek": "hex(AES-256-GCM(KEK, CEK) incl tag)"
    }
  ]
}
```

- **Payload** is the plaintext bytes (e.g. a `.traveler.zip`), so the existing
  archive rules — allowlist, size caps, META digests — apply unchanged after
  decryption.
- **Multi-recipient:** one random 256-bit CEK encrypts the payload once; per
  recipient, an ML-KEM encapsulation → HKDF-SHA-384 derives a KEK that wraps the
  CEK. An RFQ broadcast to five shops is one payload, five recipient entries.
- **AAD:** the payload's GCM associated data is the canonical JSON of
  `{spec, enc_alg, recipients: [kid, …]}` — the algorithm identifiers **and the
  ordered recipient set** are bound, so a downgrade or a dropped/reordered
  recipient fails the tag. Each wrap binds `{spec, enc_alg, kid}`.
- **Recipient keys** are resolved through the signed directory (`recipientByOrg`):
  a sealer encrypts to the ML-KEM key the trust root bound to the org, not to
  caller-supplied bytes. `kid` is derived from that key (`enc_kid`).
- **Metadata minimization:** recipients are identified only by `kid`, meaningless
  without the directory the parties already share. The envelope carries **no**
  traveler_id, org names, or part information in the clear. Filename SHOULD be
  random, not `{traveler_id}.sje`.

### Wire shape (normative, both envelope versions)

AES-GCM authenticates the payload and each wrapped key. It does **not** authenticate
the JSON around them: an extra member, a hex string in the other letter case, a
13-byte nonce, or a 16-byte content key are all outside what the tags cover or decide.
An implementation MUST therefore refuse an envelope that is not exactly this shape,
**before any key is used**:

| Element | Rule |
|---|---|
| Text | UTF-8, no byte-order mark, at most 4,325,376 bytes (2 × the 2 MiB archive limit + 128 KiB); a member name appears at most once in any object; nothing follows the envelope value |
| Envelope | an object with **exactly** `spec`, `enc_alg`, `payload_nonce`, `payload`, `recipients` |
| `spec` / `enc_alg` | `sje-envelope/0.1.0` with `ML-KEM-1024+HKDF-SHA-384+AES-256-GCM`, or `sje-envelope/0.2.0` with `ML-KEM-1024x2+HKDF-SHA-384+AES-256-GCM` — the algorithm string must be the one that belongs to the spec |
| `recipients` | an array of 1–16 entries; no `kid` appears twice |
| Recipient (0.1.0) | an object with **exactly** `kid`, `kem_ct`, `wrap_nonce`, `wrapped_cek` |
| Recipient (0.2.0) | an object with **exactly** `kid`, `prekey_id`, `kem_ct_onetime`, `kem_ct_static`, `wrap_nonce`, `wrapped_cek` |
| Hex fields | lowercase, whole bytes, exact lengths: `payload_nonce` and `wrap_nonce` 12 bytes; `kid` 8 bytes; each ML-KEM-1024 ciphertext 1568 bytes; `wrapped_cek` 48 bytes (the 32-byte content key + the 16-byte tag — so the content key is always an AES-256 key); `payload` at least 16 bytes (its tag) and at most 2 MiB + 16 |
| `prekey_id` | 1–64 characters of `A–Z a–z 0–9 . _ -` (it is concatenated into the key-derivation label, so it cannot contain a separator) |

Member order and insignificant whitespace are not part of the shape. The same rules
apply to an envelope handed over as an already-parsed value.

Both reference implementations enforce this table identically
(`envelope.ts::assertEnvelopeShape`, `envelope.rs::check_shape`), and
`conformance/signatures/envelope-cases.json` holds the cases that prove it: envelopes
both must open, envelopes both must refuse **at the shape check** (most of which would
decrypt successfully if the check were missing), and shape-valid envelopes both must
fail to open (a flipped bit, a reordered, dropped or relabelled recipient).

### Key derivation and associated data (normative)

Everything an implementation needs to produce the bytes in the golden vectors
(`conformance/signatures/envelope.json`, `fs-envelope.json`). `‖` is concatenation,
`0x00` a single zero byte, strings are UTF-8, and "canonical JSON" is SPEC §Canonical
JSON (members in code-point order, no whitespace).

| | `sje-envelope/0.1.0` | `sje-envelope/0.2.0` |
|---|---|---|
| `kid` | first 16 hex characters of SHA-384 over the recipient's static ML-KEM-1024 encapsulation key (1568 bytes) | same |
| Content key (CEK) | 32 random bytes, fresh per envelope | same |
| Payload AAD | canonical JSON of `{ "enc_alg", "recipients": [kid, …], "spec" }` — recipients in envelope order | canonical JSON of `{ "enc_alg", "recipients": [{ "kid", "prekey_id" }, …], "spec" }` |
| `payload` | AES-256-GCM(key = CEK, nonce = `payload_nonce`, AAD = payload AAD) over the plaintext; ciphertext ‖ 16-byte tag | same |
| Wrap label | `spec ‖ 0x00 ‖ enc_alg ‖ 0x00 ‖ kid` | `spec ‖ 0x00 ‖ enc_alg ‖ 0x00 ‖ kid ‖ 0x00 ‖ prekey_id` |
| Input key material | the 32-byte ML-KEM shared secret of `kem_ct` | `ss_onetime ‖ ss_static` (64 bytes): the shared secret of `kem_ct_onetime`, then that of `kem_ct_static` |
| Key-encryption key (KEK) | HKDF-SHA-384(IKM, salt = `sje-kek/0.1.0`, info = wrap label, L = 32) | same construction (the salt string is the same in both versions; the wrap label differs) |
| `wrapped_cek` | AES-256-GCM(key = KEK, nonce = `wrap_nonce`, AAD = wrap label) over the CEK; 32 bytes ‖ 16-byte tag | same |

Nonces are 12 random bytes each; a nonce is never reused under one key because every
CEK and every KEK is used for exactly one encryption. Opening reverses this for the
recipient entry whose `kid` is the opener's, then decrypts the payload under the AAD
rebuilt from **every** recipient entry in the envelope — which is what makes dropping,
adding or reordering a recipient fail for everyone.

What the construction does **not** provide, by design of the primitives:

- **Sender authentication.** Anyone who has a recipient's public key can seal an
  envelope to it. An envelope that opens says nothing about who sent it; that is the
  job of the signatures inside the traveler and of the receive policy (SPEC
  §Verification).
- **Key commitment.** AES-GCM is not key-committing: a sender can craft one envelope
  whose payload decrypts to different plaintexts under different content keys handed
  to different recipients. Recipients of one multi-recipient envelope must not assume
  they all read the same traveler; compare `traveler_hash`.
- **Metadata privacy.** `kid` is a stable pseudonym that anyone holding the directory
  can resolve to an org; the number of recipients, the envelope version, `prekey_id`
  and the payload length are visible. There is no padding.

## Forward secrecy (`sje-envelope/0.2.0`)

The 0.1 envelope encapsulates only to a recipient's long-lived static key, so a
later compromise of that key exposes every stored envelope sent to it. The 0.2
mode fixes that with **single-use prekeys** and a **two-KEM combine**:

- A recipient org publishes a **signed one-time prekey bundle**
  (`sje-prekeys/0.1.0`): a batch of one-time ML-KEM-1024 prekeys, the whole
  bundle signed by the org's ML-DSA identity key and verified against the
  directory, so a prekey is provably the org's — not an attacker's. See
  `src/lib/traveler/prekeys.ts`.
- **Seal** encapsulates to **both** a chosen one-time prekey and the static
  identity key, then derives `KEK = HKDF-SHA-384(ss_onetime ‖ ss_static, …)`.
  Each recipient entry carries `prekey_id`, `kem_ct_onetime`, and
  `kem_ct_static`; the payload AAD binds
  `{spec, enc_alg, recipients: [{kid, prekey_id}, …]}`.
- **Open** requires **both** secret keys, so a one-time secret that leaks on its own
  exposes nothing. Once the recipient has **deleted** the one-time secret, a later
  compromise of the static key cannot recover that message — forward secrecy.

**What this does and does not give you — read before relying on it.**

- *When the one-time secret is deleted.* When the traveler the envelope carried has
  been **admitted** by the recipient — not when the envelope is decrypted. Decrypting
  is not accepting: the archive checks, the receive policy and sometimes a person stand
  in between, and an envelope whose key was spent on decryption could never be opened
  again after a refusal or a closed tab (`transport.ts::openTravelerDeferred`, then
  `commit()`). Until then the same envelope can be decrypted again by whoever holds
  the keystore and its passphrase. (Earlier text here said the deletion was persisted
  "before the secret is used". The code never did that.)
- *Deletion has to reach storage.* A write that fails is reported, not assumed: the
  desk says so and the envelope remains decryptable with that keystore.
- *A prekey serves one envelope.* Nothing reserves a prekey: a sender picks one from
  the public bundle. Two envelopes sealed to the same prekey — by two senders, or by
  one sender that does not remember what it used — leave the second **permanently
  unopenable** once the first is admitted, while each sender was told "forward-secret".
  A sender SHOULD remember which prekeys of a bundle it has used and never reuse one;
  two different senders can still collide, and only a coordinating service (which this
  format deliberately does not have) could prevent that.
- *The pool can be burned.* Prekey ids and public keys are public. Anyone can seal
  valid envelopes to every prekey in a bundle; each one the recipient admits spends a
  prekey. Junk that fails the archive checks spends nothing.
- *Downgrade is silent to the recipient.* When no verifying bundle with an unused
  prekey is available, sealing falls back to the 0.1 static envelope — confidential,
  not forward-secret — and **reports it** to the sender (`forwardSecret: false`);
  `requireForwardSecret` turns the fallback into an error. A recipient cannot tell a
  sender that had no bundle from one whose bundle was withheld, and cannot refuse a
  static envelope. A bundle whose prekeys are all spent still verifies.

## Keys

- A shop's encryption identity is an ML-KEM keypair attested in the signed
  directory; its one-time prekeys are published in a signed bundle. Exchange is
  out of band, like the directory — SJE stays a file format, not a platform, with
  no central broker that sees plaintext or the exchange graph.
- **Rotation:** identity keys SHOULD rotate; a `kid` change is a new key. Old
  private keys must be retained for as long as archived (non-forward-secret)
  envelopes matter — or archives should be re-encrypted on rotation. One-time
  prekeys are the opposite: use once, then delete.
- The browser desk now holds its ML-KEM **decryption** secret, but only in a
  **passphrase-encrypted keystore** (`src/lib/traveler/keystore.ts`): encrypted at
  rest (scrypt + AES-256-GCM), decrypted in memory only while unlocked. It seals
  (encrypt-to-recipient needs only public keys, so it works locked) and opens
  (decrypt needs the unlocked secret) through `transport.ts`. It still never holds
  **ML-DSA signing** keys and never signs — prekey bundles are assembled and signed
  off the desk. Caveat: an XSS on an **unlocked** desk can read the in-memory ML-KEM
  secret (ML-KEM runs in JS); the keystore protects a stolen blob *without* the
  passphrase, not script in the origin. Signature verification remains a reference-
  library / CLI / MCP capability.

## Explicit non-goals

- Traffic-flow confidentiality from the transport itself (email headers,
  IP metadata). Use channels appropriate to the sensitivity.
- Deniability or anonymity between counterparties.
- Compliance magic: encrypting a traveler does not make a browser desk a
  CUI system. DFARS / NIST 800-171 obligations live in the parties' control
  environments (see `TRUST.md`).

## Test vectors

The golden vectors exist, and both implementations reproduce them byte-for-byte
in CI (see `docs/CLAIMS.md` PQ4, PQ7–PQ9):

- `conformance/signatures/envelope.json` — 0.1 static envelope (directory-attested
  recipient; re-seal + open + tamper).
- `conformance/signatures/prekey-bundle.json` — signed one-time prekey bundle
  (verify against the directory; tampered prekey / out-of-window / wrong root).
- `conformance/signatures/fs-envelope.json` — 0.2 forward-secret envelope
  (two-KEM combine; re-seal byte-for-byte + open with both keys + negative cases).
- `conformance/signatures/envelope-cases.json` — accept / reject cases for both
  versions, each reject case tagged with the stage that must refuse it (`shape` or
  `crypto`); includes two-recipient envelopes (open as either; reorder, drop, swap).
