# Secure Job Envelope (SJE) — spec 0.1.0

> This is the frozen base spec (canonical JSON, hash, conformance ladder, archive). 0.1 adds ML-DSA-87 authorship signatures, a signed key directory, directory-attested ITAR, integer-minor-unit money, and the encrypted envelope — see docs/CLAIMS.md and SECURITY.md.

Implementable draft. Media type `application/vnd.sje+json`.
Archive name `{traveler_id}.traveler.zip`. License MIT.

A traveler is the job object — one part family between a buyer and sellers —
not a shop OS and not a marketplace. Quotes bind to `traveler_hash_quoted`,
a SHA-384 of the canonical **quoteable body**.

## Identifiers

```
traveler_id / quote_id : ^[a-z]{3}_[a-z0-9]{6,24}$     (e.g. tvl_8kq2mfn3, qot_x91k2p)
hash                 : ^sha384:[0-9a-f]{96}$
currency             : ^[A-Z]{3}$    country: ^[A-Z]{2}$
created_at           : ISO-8601 UTC with trailing Z
```

Size caps: traveler JSON ≤ 512 KiB; archive ≤ 2 MiB; strings ≤ 2000 chars;
names ≤ 128 chars.

## The quoteable body (closed field set)

The hash covers **exactly** these fields — extra keys on in-memory objects
never enter the hash:

```
spec, traveler_id, revision, created_at, buyer, part,
need_by, incoterms, itar
```

`buyer` (Org) and `part` are themselves closed: absent optionals are
dropped, empty strings and empty arrays are dropped, `need_by`/`incoterms`
are `null` when absent, `itar` defaults to `false`. Quotes, award, ops, and
ship_to sit **outside** the hash so a traveler can climb L0→L2 without
invalidating quotes. Amending the quoteable body bumps `revision` and
stale-marks every existing quote.

**The hash is integrity of the buyer-authored body, not a signature, and
not non-repudiation.** 0.1 adds ML-DSA-87 authorship signatures over the
canonical body, verified against a signed key directory (see SECURITY.md).

## Canonical JSON

RFC 8785-inspired, restricted for cross-language byte equality:

1. Object keys sorted **lexicographically by Unicode code point** (equivalently,
   by UTF-8 byte order); compact output
   (no whitespace). Implementations must emit in that order explicitly —
   in particular, JavaScript implementations must not serialize a rebuilt
   object, because JS enumerates integer-like keys ("2", "10") in numeric
   order regardless of insertion order. Conformance vector
   `key-order-digits` pins this.
2. `undefined` / absent members are omitted entirely.
3. Strings escape per standard JSON. **Field names are ASCII** by convention.
   Non-ASCII keys are sorted by Unicode code point on both implementations
   (the TypeScript reference sorts by code point explicitly, not by UTF-16 code
   unit, matching the Rust core's UTF-8 byte order), so astral-plane keys order
   identically across languages. Conformance vector `astral-key-order` pins this.
4. **Numbers are restricted to a range where every language renders the
   same bytes and round-trips exactly.** A number is canonical iff it is
   finite, `|x| <= 9007199254740991` (2^53−1), and — when not an integer —
   `|x| >= 1e-5` (or exactly 0). Conforming implementations **refuse**
   anything else rather than hash it ambiguously. Within the range:
   - integer-valued floats emit without a trailing `.0` (thickness `10.0`
     hashes as `10`),
   - `-0` emits as `0`,
   - non-integers emit their shortest round-trip decimal in fixed
     notation (both JS `Number::toString` and Rust's ryu agree here).

   Why the bounds: above 2^53−1 integers stop being exact in an IEEE-754
   double, so a JSON round-trip through JavaScript silently changes the
   value (and the hash); below 1e-5, ryu switches to exponential notation
   (`1e-6`) while JavaScript stays fixed (`0.000001`), so the renderings
   diverge. Non-finite numbers are refused outright. The published JSON
   Schemas bound every numeric field inside this range — integer fields
   within 2^53−1, the `money` / `priceDelta` `$defs` in `quote-0.1.0.json`
   as integer minor units (`0 … 1e12` / `±1e12`), and the sole non-integer
   field, `thickness_mm`, bounded `≥ 1e-4` so it always renders in canonical
   fixed notation. The canonicalizer is the final gate and refuses anything
   outside the range regardless.

The hash is `"sha384:" + lowercase-hex(SHA-384(canonical_json_bytes))`.

**Why SHA-384:** the spec targets ≥128-bit collision resistance against a
quantum adversary. SHA-256's classical 128-bit collision bound degrades
under quantum collision search; SHA-384 keeps ≥128-bit collision and
≥192-bit (Grover) preimage margins post-quantum, at the cost of a longer
hash string. Chosen pre-release so no deployed hashes ever migrate.

Both reference implementations must reproduce the golden vector
(`crates/secure-job-envelope/tests/golden.json`) exactly.

## Conformance ladder

| Level | Name | Meaning |
|---|---|---|
| D | Draft | Missing something L0 needs |
| L0 | Quoteable | A seller can price without guessing material or qty |
| L1 | Awardable | ≥ 1 structured quote bound to the current buyer revision |
| L2 | Executable | Awarded, ops listed, ship-to present; traveler locks |
| L3 | As-built | A non-empty `as_built` object recorded on the executed traveler. Both implementations compute L3; the object's contents are not specified or covered by conformance vectors in 0.1 |

## Quotes

```
required: quote_id, seller, traveler_hash_quoted, created_at,
          valid_until, lead_time_days, pricing
pricing.required: currency, lines[]
lines[]: { qty >= 1, unit: integer minor units, 0 .. 1e12 }
```

A quote is **bound** when `traveler_hash_quoted` equals the current traveler
hash. Guards a conforming desk enforces at bind/award time: quote expiry
(`valid_until`), one quote per seller per revision, a priced line at the
target quantity, and ITAR consistency (a seller with `itar !== true` cannot
quote an `itar: true` traveler — a consistency check, not compliance).

## Archive (`{traveler_id}.traveler.zip`)

Allowlisted members only (max 3):

```
traveler.json                the traveler document (required, root only)
META.json                    integrity manifest (required, root only)
quoteable.canonical.json     canonical quoteable-body bytes (optional)
```

`META.json` carries at least `{ traveler_id, traveler_hash,
traveler_json_sha384 }` and normally also `{ spec, media_type, archive, itar,
export_control }`. Any other member — including `NOTES.txt` — is refused.

Import rules: refuse any member outside the allowlist; refuse paths
containing `/`, `\`, `..`, a leading `/`, or a NUL; cap compressed and
uncompressed sizes. Integrity is verified with SHA-384 cross-checks, not
CRC32 (CRC is deliberately skipped so a hostile archive is not fully
inflated before the guards run). `META.json` is **required** — its
`traveler_id` and `traveler_hash` must match the received `traveler.json`,
and `traveler_json_sha384` (a digest over the whole `traveler.json`) is
**required** and must match. Because `traveler_hash` covers only the quoteable
body, this full-bytes digest is what binds the non-quoteable lifecycle fields
(award, ship_to, ops, quotes, as_built); without it those could be altered
under an unchanged `traveler_hash`. When `quoteable.canonical.json` is present
it must equal your canonical rendering of the quoteable body. Re-canonicalize
and check `traveler_hash` yourself — treat the archive as the document.

These digests are **unkeyed** integrity: they detect corruption and naive
tampering, and guarantee the archive is internally consistent, but a party that
re-seals an archive recomputes them. Adversarial *authenticity* is the separate
ML-DSA authorship signature, which in 0.1 signs the quoteable body — the
lifecycle fields (award, ship_to, ops) are mutable workflow state and are not
covered by the authorship signature. A duplicate member name resolves to the
**last** entry (which is then digest-checked); an external tool that resolves
duplicates as "first" may disagree, so treat a duplicate-membered archive as
suspect.

## Export control & commercial reality

- `itar: true` is a self-declaration that the traveler contains
  ITAR-controlled technical data. 0.1 elevates this to directory attestation —
  an ITAR traveler's seller must hold the directory's attested ITAR capability,
  not merely self-declare `seller.itar`. It is still not DDTC registration, a
  TCP, or an EAR ECCN. Shop `certs[]` is for ISO/AS/AWS; the ITAR bit lives on
  `org.itar`.
- Do not put actual USML/EAR technical data on a public or shared browser
  desk. localStorage is not a CUI system (DFARS 252.204-7012 / NIST
  800-171).
- A bound quote is a structured price; an award is not a PO. The 0.0.1 base
  had no governing law, warranty, inspection, payment terms, or
  battle-of-the-forms handling; 0.1 lets an award carry optional commercial
  terms (governing law, warranty, payment), though an award is still not a
  contract by itself.
- Incoterms 2020 `FOB` is for sea/inland waterway with a named port; US
  domestic shops usually mean UCC F.O.B. origin/destination. The field is a
  free-form string in 0.1.
- Money is an integer count of the currency's minor unit (e.g. cents) in 0.1 —
  exact, no IEEE-754.

## JSON Schemas

`public/schemas/traveler-0.1.0.json` and `public/schemas/quote-0.1.0.json`
(JSON Schema 2020-12, `$id` under `https://securejobenvelope.org/schemas/`).
