# SJE — project plan

Working name. The product is a **content-addressed job envelope for parts manufacturing**, not a shop OS and not a marketplace. Shops already have ERPs and spreadsheets; coordination happens through a file `{traveler_id}.traveler.zip` that any conforming tool can hash the same way.

## Why this exists

Every job shop already has systems. A coordination *platform* asks everyone to move in. A coordination *format* meets every shop where it is: any tool that can read and write a small, hashable JSON envelope can participate, and the hash means nobody has to trust anyone's database but their own.

Buyer seals a quoteable traveler (L0) → sellers bind quotes to `traveler_hash` (L1) → buyer awards + ops + ship-to (L2) → as-built data recorded (L3).

## Goals

1. **Envelope** — Shops exchange a hash-bound job traveler without a shared database. SHA-384 of the canonical quoteable body is the identity of the revision being priced.
2. **Desk** — A buyer and a seller can compose, quote, and award that traveler from a local desk (browser workbench + independent Rust verifier).
3. **Trust** — Integrity and export-control claims are checkable, not marketing. `docs/CLAIMS.md` maps every written claim to a test; if it is not there, treat it as unverified.

## Milestones

### M-format — 0.1.0 format locked
Hash, canonical JSON, schema, conformance ladder (D → L0 → L1 → L2 → L3). Dual implementation (TypeScript + Rust) must match the golden vector.

### M-flow — Desk flow L0→L2 green
Compose, quote, award, amend/lock, import/export archive, ITAR self-declaration guards. This is the job object climbing the ladder.

### M-desk — Desk product
Home list, traveler view, shell navigation, buyer/seller role switch (a view, not auth), in-app spec, local trust/audit log.

### M-envelope — 0.1 encrypted envelope (implemented)
`.sje` for harvest-now-decrypt-later. Base 0.1 + forward-secret 0.2 are implemented in both languages; see `docs/ENVELOPE-DRAFT.md` and the `conformance/signatures/*` vectors. No Gherkin scenarios bound yet.

## Current state

- Spec `sje/0.1.0` is written (`docs/SPEC.md`, JSON Schema, 15 Gherkin features / 88 scenarios).
- TypeScript desk and Rust crate already implement hash, guards, zip, golden vector.
- Shalt ledger: **88 scenarios, all pending** (no cucumber-rs steps bound yet). The desk has its own `npm test` suite; shalt Play has not made those green.
- `shalt.toml` stack is **rust** (`cargo test --test shalt`). The desk is TypeScript. Do not Play the whole repo as rust until the runner matches the thing under test — either a rust shalt harness for the crate, or a javascript stack for the desk.

## What “done” means here

Gherkin wins. A milestone is done when its scenarios are **green and hash-bound**, not when the README sounds finished. Pending is not green.

## Out of scope for 0.1

Still out of scope: identity and tenancy, real ITAR / export-control compliance (the `itar` bit is a self-declaration; 0.1 adds directory attestation in the reference library, not compliance). Shipped in 0.1 (were out of scope in 0.0.1): ML-DSA-87 party authentication, integer money, optional award commercial terms, L3 as-built, and the encrypted envelope (base + forward-secret).
