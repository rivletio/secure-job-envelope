# Encrypted envelope — draft for 0.1

**Status: DRAFT — design document, not yet implemented or normative.**
File extension `.jobseal`. Goal: a traveler exchanged between two shops is
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

Design consequence of the second point: JobSeal remains a **file
format, not a platform** — there is deliberately no central broker that
sees plaintext or the full exchange graph. Anyone who builds a relay or
directory on top of this spec should treat that property as normative.

## Algorithm suite (CNSA 2.0-aligned)

All primitives are NIST-standardized and chosen to sit inside CNSA 2.0 so
the same envelope serves commercial shops and the defense industrial base:

| Purpose | Algorithm | Note |
|---|---|---|
| Key establishment | **ML-KEM-768** (FIPS 203) | `ML-KEM-1024` allowed for high-assurance profiles; identifier is explicit |
| Payload encryption | **AES-256-GCM** | 256-bit key; Grover-adjusted margin ~128-bit |
| KDF | **HKDF-SHA-384** | matches the format's hash family |
| Content addressing | **SHA-384** | unchanged from the base spec |
| Sender authenticity (optional in 0.1) | **ML-DSA-65** (FIPS 204) or **SLH-DSA** (FIPS 205) | signature over the envelope header + payload hash |

No classical-only key exchange is permitted in any profile. A hybrid
(X25519 + ML-KEM) profile MAY be defined for interop during transition;
if defined, the derived key MUST bind both shared secrets.

## Envelope shape

A `.jobseal` is a JSON document (same ethos as the traveler — inspectable
structure, opaque payload):

```jsonc
{
  "spec": "jobseal-envelope/0.1",
  "enc_alg": "ML-KEM-768+HKDF-SHA-384+AES-256-GCM",
  "recipients": [
    {
      "kid": "b64u(SHA-384(recipient ML-KEM public key))[0..16]",
      "kem_ct": "b64u(ML-KEM ciphertext)",
      "wrapped_cek": "b64u(AES-256-GCM(KEK, CEK))",
      "wrap_nonce": "b64u(96-bit)"
    }
  ],
  "nonce": "b64u(96-bit)",
  "ciphertext": "b64u(AES-256-GCM(CEK, payload))",
  "signature": {                      // optional in 0.1
    "alg": "ML-DSA-65",
    "signer_kid": "…",
    "sig": "b64u(…)"
  }
}
```

- **Payload** is the complete `.traveler.zip` bytes (so the existing archive
  rules — allowlist, size caps, META digests — apply unchanged after
  decryption).
- **Multi-recipient:** one random 256-bit CEK encrypts the payload once; a
  per-recipient ML-KEM encapsulation derives (via HKDF-SHA-384, with the
  envelope's `spec` and `enc_alg` strings as info/context) a KEK that
  wraps the CEK. An RFQ broadcast to five shops is one payload, five
  recipient entries.
- **AAD:** the GCM associated data for the payload encryption is the
  canonical JSON of `{spec, enc_alg}` — algorithm identifiers are bound so
  they cannot be stripped or downgraded without failing the tag. Recipient
  entries bind `{spec, enc_alg, kid}` the same way.
- **Metadata minimization:** recipients are identified only by `kid` — a
  truncated hash of their public key, meaningless without the key
  directory the parties already share. Envelope carries **no** traveler_id,
  org names, or part information in the clear. Filename SHOULD be random,
  not `{traveler_id}.jobseal`.

## Keys

0.1 keeps key management deliberately primitive and honest:

- A shop's encryption identity is an ML-KEM keypair; its `kid` is
  published alongside the org's existing contact channels (email
  signature, portal profile, letterhead). Exchange is out-of-band;
  verification is fingerprint comparison. TOFU is acceptable between
  established trading partners; it is not acceptable for first contact on
  a defense-adjacent job.
- **Rotation:** keys SHOULD rotate annually; a `kid` change is a new key.
  Old private keys must be retained for as long as archived envelopes
  matter — or archives should be re-encrypted on rotation.
- **No forward secrecy in 0.1** (static recipient keys): compromise of a
  recipient's private key exposes every envelope ever sent to that key
  that the adversary retained. Mitigations: rotation, re-encryption of
  archives, and — where both parties support it — per-thread ephemeral
  recipient keys. A future version may adopt an HPKE-style construction
  once PQ HPKE is standardized.
- A signed **key directory** (org → kid → key, signed with ML-DSA) is the
  natural companion spec, and belongs with the signature/identity work in
  0.1 — until it exists, the security of first contact is the security of
  the channel the key traveled over.

## Explicit non-goals (0.1)

- Traffic-flow confidentiality from the transport itself (email headers,
  IP metadata). Use channels appropriate to the sensitivity.
- Deniability or anonymity between counterparties.
- Compliance magic: encrypting a traveler does not make a browser desk a
  CUI system. DFARS/NIST 800-171 obligations live in the parties' control
  environments (see `TRUST.md`).

## Test vectors

Before this draft becomes normative it requires, like the base spec, a
golden vector set: fixed ML-KEM keypair (test-only), fixed CEK and nonces,
a known payload, and byte-exact expected envelope JSON — implemented
independently in TypeScript and Rust with matching output, plus negative
vectors (stripped AAD, swapped `enc_alg`, truncated tag, wrong-kid
unwrap).
