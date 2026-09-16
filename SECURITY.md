# Security

## Reporting

Report vulnerabilities to **security@rivlet.io**. Please include a
reproduction; we aim to acknowledge within two business days. Do not open a
public issue for an unpatched vulnerability.

## Threat model (0.0.1)

What the format defends, by design:

- **Body integrity.** `packet_hash` is SHA-384 over a canonical rendering
  of a **closed** field set; extra keys never enter the hash, and both
  reference implementations must reproduce the shared golden vector byte
  for byte. Numbers outside the cross-language-safe range are refused, not
  hashed (see `docs/SPEC.md` § Canonical JSON).
- **Quote binding.** A quote binds to the exact buyer revision it priced
  via `packet_hash_quoted`; amending the body stale-marks every quote.
- **Hostile archives.** `.rivpkt.zip` import allowlists members (max 3),
  refuses path traversal, caps compressed and uncompressed sizes, verifies
  CRC32, and cross-checks META.json digests.
- **ID generation** uses `crypto.getRandomValues` with rejection sampling
  (no modulo bias).

What the format does **not** defend — known, stated, and the roadmap for
future versions:

- **No signatures.** The hash is integrity, not authentication. Any party
  can author a quote claiming any `seller.org_id`. Treat the transport
  channel (email, portal) as the trust anchor until packets are signed.
- **No identity or tenancy.** The desk's Buyer/Seller toggle is a view.
- **No confidentiality.** Packet JSON is plaintext; encrypt in transit and
  at rest with your own tooling.
- **Quotes are outside the hash** (deliberately, so packets can climb
  levels without invalidating prices) — a quote's own content is covered
  only by the archive's META.json digests, not by `packet_hash`.

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
- **Signatures (0.1 roadmap): post-quantum from day one.** The plan is
  **ML-DSA-65 (FIPS 204)** as the primary scheme, with **SLH-DSA
  (FIPS 205)** — hash-based, the most conservative assumption set, matching
  a spec whose only trust primitive is a hash — as a supported alternative
  for parties that want it. A transitional hybrid (Ed25519 + ML-DSA) may be
  offered for ecosystem compatibility; a packet's signature block will
  carry the algorithm identifier so verifiers reject schemes they do not
  accept.
- **Confidentiality: encrypted envelope drafted for 0.1.** 0.0.1 defines
  no encryption; the 0.1 envelope draft ([docs/ENVELOPE-DRAFT.md](docs/ENVELOPE-DRAFT.md))
  specifies ML-KEM-768 + HKDF-SHA-384 + AES-256-GCM, multi-recipient,
  CNSA 2.0-aligned, with metadata minimization as a design requirement —
  the threat model is harvest-now-decrypt-later at industrial-base scale.

## Handling of sensitive data

Do not place ITAR/EAR-controlled technical data in packets handled by the
demo desk; see `TRUST.md`.
