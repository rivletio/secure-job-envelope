# Trust — what this gives you, and what it does not

## Disclaimer

SJE is provided under the MIT License, "as is" and without warranty of any kind (see [LICENSE](LICENSE)). Nothing here — the spec, the implementations, the desk, or the security docs — is a warranty, guarantee, or assurance of security, correctness, or fitness for any purpose. Its security is best-effort and has not been independently audited. Selecting NIST/CNSA 2.0 algorithms is an engineering choice, not a certification: SJE is not SOC 2, FIPS, CNSA 2.0, ITAR, DFARS, or NIST 800-171 compliant, and using it does not make your system compliant. It is not legal or export-control advice — meeting your ITAR/EAR and CUI (DFARS 252.204-7012 / NIST 800-171) obligations is your responsibility, and controlled technical data does not belong on a shared browser desk. To the fullest extent permitted by law, Rivlet, Inc. accepts no liability arising from use of this software.

SJE is a content-addressed job object. In 0.1, authorship signatures
(ML-DSA-87, verified against a signed key directory) establish identity; CUI
handling and a production control environment remain out of band and are the
operator's responsibility.
This page maps the desk honestly against SOC 2 Trust Services Criteria so a
shop that already has SOC 2 knows exactly what is theirs to provide.

Plain statements first:

- **Buyer/Seller on the desk is a view switch** — not login, not tenancy,
  not least-privilege.
- **`traveler_hash` is integrity of the quoteable body** — not, by itself, a
  signature. 0.1 adds ML-DSA-87 authorship signatures verified against the
  signed directory; a quote that is unsigned or fails directory verification
  does not establish the seller's identity.
- **Archive import is defensive**: allowlisted members, size caps,
  path-traversal refusal, and SHA-384 META.json digest cross-checks (CRC32 is
  deliberately skipped so a hostile archive is not fully inflated first).
- **Key custody**: the desk now holds its ML-KEM *decryption* key, but only in a
  passphrase-encrypted keystore (encrypted at rest; in memory only while
  unlocked). What is *sent* between parties is an encrypted `.sje`, not plaintext.
  The desk never holds *signing* keys. An XSS on an **unlocked** desk can read the
  in-memory secret — lock when done.
- **ITAR**: 0.1 defines a directory-attested capability (reference library /
  CLI); the desk itself enforces only the self-declared `seller.itar` bit.
  Neither is a Technology Control Plan, DDTC registration, or deemed-export
  screen.

## SOC 2 TSC mapping (desk, 0.1)

| TSC | What the desk does | What your control environment still owes |
|---|---|---|
| CC6 Access | Local role switch. No identity, session, or MFA. | SSO / IdP, RBAC, joiner-mover-leaver, session timeout. |
| CC6.7 Restrict data | Origin-isolated localStorage. Secret keys encrypted at rest (scrypt + AES-256-GCM keystore, unlocked in memory only); working traveler state is plaintext localStorage. | CUI boundary, full-disk/at-rest encryption for working data, DLP, media control. |
| CC7 Monitoring | Append-only local audit of compose/quote/award/import/export, capped at 100 events, no PII in the log. | Central immutable log, alerting, retention, clock sync. |
| CC8 Change | Hash-bound quotes; 0.1 adds ML-DSA-87 authorship signatures, verified against the signed directory in the reference library / CLI (not wired into the desk UI). Amend bumps revision and stale-marks quotes. L2 travelers lock. | Change tickets, dual control on award, signature verification in the desk, and the signing-key custody the desk does not hold (it holds only the ML-KEM decryption key, encrypted — see SECURITY). |
| A1 Availability | This browser tab. | HA, backup, RTO/RPO, incident response. |
| C1 Confidentiality | The sent artifact is an encrypted `.sje` (ML-KEM-1024 + AES-256-GCM), addressed via the signed directory; local working-state JSON is readable on the desk, and TLS still applies to the page itself. | Classification, NDAs, vendor review, confidentiality of working data at rest. |
| P1 Privacy | Ship-to is stored with the traveler when awarded. Audit log omits addresses. | Minimization, retention, DSAR, subprocessors. |

## Controlled data

Do **not** put USML / EAR technical data on a public or shared browser
desk. localStorage is not a CUI system (DFARS 252.204-7012 / NIST 800-171).
The desk demonstrates the traveler envelope, not a home for controlled
drawings.
