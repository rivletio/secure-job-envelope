# Security

## Reporting

Report vulnerabilities to **security@rivlet.io**. Please include a
reproduction; we aim to acknowledge within two business days. Do not open a
public issue for an unpatched vulnerability.

## Threat model (0.0.1)

What the format defends, by design:

- **Body integrity.** `packet_hash` is SHA-256 over a canonical rendering
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

## Handling of sensitive data

Do not place ITAR/EAR-controlled technical data in packets handled by the
demo desk; see `TRUST.md`.
