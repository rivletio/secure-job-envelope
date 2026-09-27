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
  key's `org_id` differs from the body's is refused, closing org_id spoofing.
- **Confidentiality (0.1).** The encrypted envelope (ML-KEM-1024 +
  HKDF-SHA-384 + AES-256-GCM) protects payloads in transit and at rest, with
  AEAD binding the spec/alg/recipient so a stripped or swapped field fails.

What the format does **not** defend — known, stated, and the roadmap for
future versions:

- **No multi-tenant access control.** The signed directory establishes
  *identity* (org_id → key with attested capabilities), but there is no
  per-tenant authorization layer; the desk's Buyer/Seller toggle is a view.
- **No forward secrecy.** The envelope encapsulates to a recipient's static
  ML-KEM key, so a future compromise of that key exposes past envelopes sent
  to it. Single-use prekeys (PQXDH-style) are the next envelope milestone.
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
  security. This was fixed **before first release**, so no fielded hash
  ever migrates.
- **Signatures (0.1): implemented, pure CNSA 2.0 Category 5.** **ML-DSA-87
  (FIPS 204)** authorship signatures over the domain-separated canonical body,
  verified against a signed key directory (org_id → key, with attested
  capabilities including ITAR). Every signature carries its `alg`; verifiers
  reject schemes they do not accept. SLH-DSA (FIPS 205) — hash-based, the most
  conservative assumption set — remains a supported alternative on the roadmap
  (NIST, not a CNSA 2.0 algorithm). Signing keys stay off the browser desk,
  which verifies only.
- **Confidentiality (0.1): implemented, pure CNSA 2.0 Category 5.** The
  encrypted envelope ([docs/ENVELOPE-DRAFT.md](docs/ENVELOPE-DRAFT.md)) is
  **ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM**, multi-recipient, with metadata
  minimization and AAD binding {spec, enc_alg, kid} — the threat model is
  harvest-now-decrypt-later at industrial-base scale. Both the signatures and
  the envelope ship with dual-language golden vectors. Forward secrecy
  (single-use prekeys) is the next milestone.

## Handling of sensitive data

Do not place ITAR/EAR-controlled technical data in travelers handled by the
demo desk; see `TRUST.md`.
