# Security

## Reporting

Report vulnerabilities to **security@rivlet.io**. Please include a
reproduction; we aim to acknowledge within two business days. Do not open a
public issue for an unpatched vulnerability.

## Threat model (0.1)

What the format defends, by design:

- **Body integrity.** `traveler_hash` is SHA-384 over a canonical rendering
  of a **closed** field set; extra keys never enter the hash, and both
  reference implementations must reproduce the shared golden vector byte
  for byte. Numbers outside the cross-language-safe range are refused, not
  hashed (see `docs/SPEC.md` § Canonical JSON).
- **Quote binding.** A quote binds to the exact buyer revision it priced
  via `traveler_hash_quoted`; amending the body stale-marks every quote.
- **Hostile archives.** `.traveler.zip` import allowlists members (max 3),
  refuses path traversal, caps compressed and uncompressed sizes, verifies
  CRC32, and cross-checks META.json digests.
- **ID generation** uses `crypto.getRandomValues` with rejection sampling
  (no modulo bias); there is no non-cryptographic fallback.
- **Party authentication (0.1).** ML-DSA-87 (FIPS 204) authorship signatures
  bind a traveler/quote to a key in a signed directory; a signature whose
  key's `org_id` differs from the body's — or that names no org at all — is
  refused. The desk verifies signatures only and never holds signing keys.
- **Confidentiality (0.1).** The encrypted envelope (ML-KEM-1024 +
  HKDF-SHA-384 + AES-256-GCM) is designed to keep payloads confidential in
  transit and at rest against a harvest-now-decrypt-later adversary, subject to
  the key-management limits below (no forward secrecy in 0.1). AEAD binds
  `{spec, enc_alg, recipients}` to the payload and `{spec, enc_alg, kid}` to
  each wrap, so a stripped, swapped, or reordered field/recipient fails the tag;
  recipient keys are resolved through the signed directory.

What the format does **not** defend — known, stated, and the roadmap for
future versions:

- **No multi-tenant access control.** The signed directory establishes
  *identity* (org_id → key with attested capabilities), but there is no
  per-tenant authorization layer; the desk's Buyer/Seller toggle is a view.
- **No forward secrecy.** The envelope encapsulates to a recipient's static
  ML-KEM key — bound to the org through the signed directory, but long-lived —
  so a future compromise of that key exposes past envelopes sent to it.
  Single-use prekeys (PQXDH-style) are the next envelope milestone.
- **Quotes are outside the hash** (deliberately, so travelers can climb
  levels without invalidating prices) — a quote's content is covered by its
  own seller signature and the archive's META.json digests, not by
  `traveler_hash`.

## Proving these claims

Every claim in this document is either proven by a named test (both
implementations, in CI) or explicitly labeled a draft. The mapping lives
in [docs/CLAIMS.md](docs/CLAIMS.md); the shared vector corpus lives in
[conformance/](conformance/).

## Post-quantum posture

- **Hashing: SHA-384.** The content address must hold ≥128-bit collision
  resistance against a quantum adversary. SHA-256 offers 128-bit collision
  resistance classically, but quantum collision search erodes that margin;
  SHA-384 keeps ≥128-bit collision and ~192-bit (Grover-adjusted) preimage
  security. This was fixed **before first release** to avoid a later hash
  migration.
- **Signatures (0.1): implemented; algorithms from the CNSA 2.0 Category 5 suite.** **ML-DSA-87
  (FIPS 204)** authorship signatures over the domain-separated canonical body,
  verified against a signed key directory (org_id → key, with attested
  capabilities including ITAR). Every signature carries its `alg`; verifiers
  reject schemes they do not accept. SLH-DSA (FIPS 205) — hash-based, the most
  conservative assumption set — remains a supported alternative on the roadmap
  (NIST, not a CNSA 2.0 algorithm). Signing keys stay off the browser desk,
  which verifies only.
- **Confidentiality (0.1): implemented; algorithms from the CNSA 2.0 Category 5 suite.** The
  encrypted envelope ([docs/ENVELOPE-DRAFT.md](docs/ENVELOPE-DRAFT.md)) is
  **ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM**, multi-recipient, with metadata
  minimization, recipient keys resolved through the signed directory, and AAD
  binding {spec, enc_alg, recipients} (payload) / {spec, enc_alg, kid} (wraps) —
  the threat model is harvest-now-decrypt-later at industrial-base scale. Both
  the signatures and the envelope ship with dual-language golden vectors.
  Forward secrecy (single-use prekeys) is the next milestone.

## Handling of sensitive data

Do not place ITAR/EAR-controlled technical data in travelers handled by the
demo desk; see `TRUST.md`.

## No warranty

This is best-effort security, not a guarantee, and it has **not** been
independently audited. Selecting NIST / CNSA 2.0 algorithms is an engineering
choice, not a certification: SJE is **not** SOC 2, FIPS, CNSA 2.0, ITAR, DFARS,
or NIST 800-171 compliant, and using it does not make your system compliant.
Nothing here is legal or export-control advice. See the Disclaimer in the
[README](README.md).
