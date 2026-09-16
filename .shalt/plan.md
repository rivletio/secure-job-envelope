# Rivlet Packet — project plan

Working name. The product is a **content-addressed job envelope for parts manufacturing**, not a shop OS and not a marketplace. Shops already have ERPs and spreadsheets; coordination happens through a file `{packet_id}.rivpkt.zip` that any conforming tool can hash the same way.

## Why this exists

Every job shop already has systems. A coordination *platform* asks everyone to move in. A coordination *format* meets every shop where it is: any tool that can read and write a small, hashable JSON envelope can participate, and the hash means nobody has to trust anyone's database but their own.

Buyer seals a quoteable packet (L0) → sellers bind quotes to `packet_hash` (L1) → buyer awards + ops + ship-to (L2). L3 as-built is reserved.

## Goals

1. **Envelope** — Shops exchange a hash-bound job packet without a shared database. SHA-384 of the canonical quoteable body is the identity of the revision being priced.
2. **Desk** — A buyer and a seller can compose, quote, and award that packet from a local desk (browser workbench + independent Rust verifier).
3. **Trust** — Integrity and export-control claims are checkable, not marketing. `docs/CLAIMS.md` maps every written claim to a test; if it is not there, treat it as unverified.

## Milestones

### M-format — 0.0.1 format locked
Hash, canonical JSON, schema, conformance ladder (D → L0 → L1 → L2, L3 reserved). Dual implementation (TypeScript + Rust) must match the golden vector.

### M-flow — Desk flow L0→L2 green
Compose, quote, award, amend/lock, import/export archive, ITAR self-declaration guards. This is the job object climbing the ladder.

### M-desk — Desk product
Home list, packet view, shell navigation, buyer/seller role switch (a view, not auth), in-app spec, local trust/audit log.

### M-envelope — 0.1 encrypted envelope (draft)
`.rivpkt.enc` for harvest-now-decrypt-later. Design lives in `docs/ENVELOPE-DRAFT.md`. No scenarios yet — do not pretend this is in 0.0.1.

## Current state

- Spec `rivlet-packet/0.0.1` is written (`docs/SPEC.md`, JSON Schema, 15 Gherkin features / 88 scenarios).
- TypeScript desk and Rust crate already implement hash, guards, zip, golden vector.
- Shalt ledger: **88 scenarios, all pending** (no cucumber-rs steps bound yet). The desk has its own `npm test` suite; shalt Play has not made those green.
- `shalt.toml` stack is **rust** (`cargo test --test shalt`). The desk is TypeScript. Do not Play the whole repo as rust until the runner matches the thing under test — either a rust shalt harness for the crate, or a javascript stack for the desk.

## What “done” means here

Gherkin wins. A milestone is done when its scenarios are **green and hash-bound**, not when the README sounds finished. Pending is not green.

## Out of scope for 0.0.1

Signatures / party authentication, identity and tenancy, real ITAR compliance (the bit is a self-declaration), purchase-order semantics, integer money, L3 as-built.
