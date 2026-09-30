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
- **Open** requires **both** secret keys. Afterwards the recipient **deletes the
  one-time secret** — once it is gone, a later compromise of the static key
  cannot recover that message (forward secrecy). If a one-time prekey is ever
  reused or mishandled, the static half still keeps the payload confidential
  (graceful degradation).

**Honest boundary:** the format *enables* forward secrecy (single-use keys and a
combine that binds both secrets); actually realizing it depends on the recipient
deleting the consumed one-time secret. When no unused prekey is available,
`fsRecipientFromBundle` returns nothing and a caller must instead use the 0.1
static envelope (confidential, but not forward-secret) — there is no automatic
fallback.

## Keys

- A shop's encryption identity is an ML-KEM keypair attested in the signed
  directory; its one-time prekeys are published in a signed bundle. Exchange is
  out of band, like the directory — SJE stays a file format, not a platform, with
  no central broker that sees plaintext or the exchange graph.
- **Rotation:** identity keys SHOULD rotate; a `kid` change is a new key. Old
  private keys must be retained for as long as archived (non-forward-secret)
  envelopes matter — or archives should be re-encrypted on rotation. One-time
  prekeys are the opposite: use once, then delete.
- The browser desk never holds ML-KEM or ML-DSA secret keys and never signs or
  seals. Envelope and signature verification are implemented in the reference
  library (and available to CLI / MCP consumers), not wired into the desk UI.

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
