# Governance — the trust root and vendor neutrality

Everything authenticity in SJE rests on one thing: a **signed key directory**
that binds `org_id → public key` (with validity windows and attested
capabilities). Signatures on travelers, quotes, and awards are only as
meaningful as the directory a verifier checks them against, and the directory is
only as meaningful as the **root key** that signs it. So the fair question is:

> Who holds the root key? Can anyone else run a directory, or does trusting SJE
> mean trusting one vendor?

This page answers that. It is the design (settled and tested), followed by
Rivlet's trust-model policy: neutrality is a firm commitment, while the
operational specifics of any Rivlet-operated root remain to be finalized.

## The trust model is root-agnostic

**No root key is baked into the format or the code.** The verifier is *handed*
the root public key:

```ts
verifyDirectory(dir, rootPublicKeyHex, at)   // rootPublicKeyHex is a parameter
```

There is no default root, no hardcoded Rivlet key, no built-in authority to
appeal to. A verifier trusts **exactly** the root public key it was configured
with, out of band, and nothing more. This is the same posture as a TLS trust
store or an SSH `known_hosts` file: the format defines *how* a root attests
identities; *which* root you trust is your decision.

Three consequences follow directly, and each is pinned by a test
(`src/lib/traveler/directory.test.ts`, describe **"trust-root governance —
vendor neutrality"**):

1. **Anyone can operate a directory.** Running a directory is: generate an
   ML-DSA-87 root keypair, publish entries, sign the canonical body
   (`signDirectory`). No registration with Rivlet or anyone else is required, and
   nothing in the code privileges one root's signature over another's.
2. **Independent roots coexist (federation).** Two roots can each publish a
   directory — even binding the *same* `org_id` to *different* keys — and each
   verifies only under its own root key. A buyer and seller agree out of band on
   the root (or roots) they both trust, exactly as two companies today agree on a
   CA or exchange PGP fingerprints.
3. **The configured root is the sole arbiter.** Swap the root key a verifier
   trusts and the *same directory bytes* flip from authoritative to rejected.
   There is no vendor in the loop at verification time.

## What the root signs — and what it does not control

The root signs the directory body: the set of `org_id → key` bindings, each
entry's `[valid_from, valid_until)` window and `status`, the attested
capabilities (e.g. ITAR), and the directory's own `[issued_at, valid_until)`
freshness window. That is the whole of the root's authority.

The root does **not** sign travelers, quotes, or awards — those are signed by the
*orgs* the directory names (the buyer signs its traveler and its award; a seller
signs its quote). The root cannot forge a party's traveler or award; it can only
attest which key belongs to which org. A compromised or malicious root can
mis-bind an identity (attest the wrong key for an org) or withhold a revocation,
but it cannot by itself produce a valid buyer award signature for an org whose
signing key it does not hold. Identity attestation and authorship are separate
layers on purpose.

## Operating a directory responsibly

For anyone running a root (Rivlet or otherwise), the format gives you the
mechanisms; policy is yours:

- **Root key custody.** The root signing key is the most sensitive key in the
  system — treat it as an offline/HSM-held CA key, not a desk key. It never
  touches the browser desk (which holds no signing keys at all).
- **Validity windows bound replay.** Both the directory's own window and each
  entry's window are inside the signed body, so they cannot be widened without
  re-signing. A short directory `valid_until` bounds how long a stale (but
  validly signed) directory can be replayed after a revocation — the in-band
  limit on revocation rollback (see `docs/CLAIMS.md` PQ5). Re-issue on a cadence
  shorter than your acceptable rollback window.
- **Revocation** is `status: "revoked"` (or letting an entry's window lapse) in
  the next issued directory; there is no separate CRL/OCSP. This makes freshness,
  not just signature validity, part of trust — publish and distribute new
  directories promptly.
- **Key rotation** is additive: an org may hold several overlapping in-window
  entries during a rotation, and capability/identity checks scan *all* of them
  order-independently (`orgHasCapability`, matching the Rust verifier).

## Rivlet's role

The architecture above requires no Rivlet-operated root, and the repository ships
none. Rivlet's policy on top of it:

- **Neutrality is a commitment, not just a property.** SJE is root-agnostic by
  construction, and Rivlet commits to keeping it so: the format and the reference
  verifiers will never privilege a Rivlet-operated root over any other. Any
  party — a customer, a competitor, or an industry consortium — may operate a
  directory and be a root on exactly equal footing. Trusting SJE does not require
  trusting Rivlet.

- **Rivlet may operate a reference directory — as one root among many, never a
  required one.** Where it is useful, Rivlet may run a managed, audited directory
  that organizations can *choose* to trust, the way one chooses a certificate
  authority or a managed-DNS provider. That choice is a convenience and a
  commercial relationship, not a dependency of the format: a verifier configured
  to trust a different root, or a consortium's, interoperates identically. No
  deployment is ever obliged to point at a Rivlet root.

- **Value is captured above the protocol, not by controlling it.** The spec, the
  two reference implementations, the conformance vectors, and the verifier stay
  open and neutral — that openness is what makes the format worth adopting. Where
  Rivlet earns revenue is in the layers above it: operating a trusted directory
  (uptime, revocation SLA, audit, and the identity onboarding by which an
  `org_id` is proven to belong to a real organization before a key is attested),
  and the desk and shop-floor tooling built on the open format. The standard is
  free; the operation and the products are not.

- **Federation and a consortium path stay open.** For regulated or multi-party
  settings, roots may be run by the parties themselves or by a neutral body (a
  trade association, a buyer consortium). SJE already supports multiple
  independent and federated roots (see the tests above), and Rivlet will not
  stand in the way of that becoming the long-term home for roots where the market
  wants it.

**Still to be finalized** (operational, not architectural — none of it changes
the neutrality above): if and when Rivlet operates a *production* root, the
key-custody model (HSM, quorum / dual-control, recovery), the publication
endpoint and re-issue cadence, the revocation SLA, and the `org_id` onboarding
criteria will be set out in a separate trust-policy before that root is used in
production. Until then the repository ships no Rivlet root and every deployment
configures its own.

## Proof

| Claim | Test |
|---|---|
| The root is a verifier parameter; no root is baked in | `verifyDirectory(dir, rootPublicKeyHex, at)` signature — `src/lib/traveler/directory.ts` |
| Two independent roots each operate a directory, trusted only under their own key | `directory.test.ts` → "lets two independent roots each operate a directory…" |
| The configured root is the sole arbiter (swapping it changes the verdict) | `directory.test.ts` → "makes the configured root the sole arbiter…" |
| Freshness/validity windows are signed and bound replay (revocation rollback) | `docs/CLAIMS.md` PQ5 |

See also: [`SECURITY.md`](SECURITY.md) (threat model), [`TRUST.md`](TRUST.md)
(SOC 2 mapping), [`docs/CLAIMS.md`](docs/CLAIMS.md) (every claim → its test).
