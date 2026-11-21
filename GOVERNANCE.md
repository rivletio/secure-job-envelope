# Governance — the trust root and vendor neutrality

Everything authenticity in SJE rests on one thing: a **signed key directory**
that binds `org_id → public key` (with validity windows and attested
capabilities). Signatures on travelers, quotes, and awards are only as
meaningful as the directory a verifier checks them against, and the directory is
only as meaningful as the **root key** that signs it. So the fair question is:

> Who holds the root key? Can anyone else run a directory, or does trusting SJE
> mean trusting one vendor?

This page answers that. It is the design (which is settled and tested) followed
by the operational policy for the Rivlet reference directory (which is a
deliberate **stub** — a business decision, not a code decision).

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

## Rivlet's role — policy stub

> **This section is a deliberate stub for Rivlet to complete.** The design above
> stands on its own and requires no Rivlet-operated root. The following are
> business/policy decisions, not technical ones, and are intentionally left open
> here so they are decided explicitly rather than by default:
>
> - **Does Rivlet operate a reference root at all**, or does SJE ship only the
>   mechanism and leave every deployment to run its own? (The repository ships
>   **no** Rivlet root key, and nothing depends on one.)
> - If Rivlet does operate a root: **who in Rivlet holds the key and under what
>   custody** (HSM, quorum/dual-control, recovery), the **publication endpoint
>   and cadence**, the **revocation SLA**, and the **onboarding criteria** for
>   adding an `org_id` (how identity is proven before a key is attested).
> - **Neutrality commitment:** whether Rivlet commits, in writing, that the
>   format and verifiers will never privilege a Rivlet root over any other — i.e.
>   that a competitor or an industry consortium may run a root on equal footing.
> - **Multi-root / consortium path:** whether a neutral body (e.g. a trade
>   association or the parties' own mutual agreement) is the intended long-term
>   home for roots in regulated settings.
>
> Until Rivlet fills this in, the honest statement is: *SJE is root-agnostic by
> construction; there is no Rivlet root in this repository, and trusting SJE does
> not require trusting Rivlet.*

## Proof

| Claim | Test |
|---|---|
| The root is a verifier parameter; no root is baked in | `verifyDirectory(dir, rootPublicKeyHex, at)` signature — `src/lib/traveler/directory.ts` |
| Two independent roots each operate a directory, trusted only under their own key | `directory.test.ts` → "lets two independent roots each operate a directory…" |
| The configured root is the sole arbiter (swapping it changes the verdict) | `directory.test.ts` → "makes the configured root the sole arbiter…" |
| Freshness/validity windows are signed and bound replay (revocation rollback) | `docs/CLAIMS.md` PQ5 |

See also: [`SECURITY.md`](SECURITY.md) (threat model), [`TRUST.md`](TRUST.md)
(SOC 2 mapping), [`docs/CLAIMS.md`](docs/CLAIMS.md) (every claim → its test).
