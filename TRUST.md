# Trust — what this gives you, and what it does not

JobSeal is a content-addressed job object. Identity, signatures, CUI
handling, and a production control environment are **out of band in 0.0.1**.
This page maps the desk honestly against SOC 2 Trust Services Criteria so a
shop that already has SOC 2 knows exactly what is theirs to provide.

Plain statements first:

- **Buyer/Seller on the desk is a view switch** — not login, not tenancy,
  not least-privilege.
- **`traveler_hash` is integrity of the quoteable body** — not a signature,
  not non-repudiation. Anyone can mint a quote claiming to be a named shop.
- **Archive import is defensive**: allowlisted members, size caps, CRC32,
  path-traversal refusal, and META.json digest cross-checks.
- **ITAR is a self-declared bit** plus a quote/award consistency check. It
  is not a Technology Control Plan, DDTC registration, or deemed-export
  screen.

## SOC 2 TSC mapping (desk, 0.0.1)

| TSC | What the desk does | What your control environment still owes |
|---|---|---|
| CC6 Access | Local role switch. No identity, session, or MFA. | SSO / IdP, RBAC, joiner-mover-leaver, session timeout. |
| CC6.7 Restrict data | Origin-isolated localStorage. No encryption at rest. | CUI boundary, encryption at rest, DLP, media control. |
| CC7 Monitoring | Append-only local audit of compose/quote/award/import/export, capped at 100 events, no PII in the log. | Central immutable log, alerting, retention, clock sync. |
| CC8 Change | Hash-bound quotes. Amend bumps revision and stale-marks quotes. L2 travelers lock. | Change tickets, signed travelers, dual control on award. |
| A1 Availability | This browser tab. | HA, backup, RTO/RPO, incident response. |
| C1 Confidentiality | TLS in transit if the host serves HTTPS. Traveler JSON is readable. | Classification, encryption, NDAs, vendor review. |
| P1 Privacy | Ship-to is stored with the traveler when awarded. Audit log omits addresses. | Minimization, retention, DSAR, subprocessors. |

## Controlled data

Do **not** put USML / EAR technical data on a public or shared browser
desk. localStorage is not a CUI system (DFARS 252.204-7012 / NIST 800-171).
The desk demonstrates the traveler envelope, not a home for controlled
drawings.
