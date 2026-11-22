# sim/findings — findings of the differential fuzzer

A wire document the two implementations judge differently (or that crashes or
stalls one of them), found by `npm run differential`. While a finding is **open** it
is kept here as its minimized bytes, both verdicts, and a diagnosis. The fuzzer is not
told about open findings: it keeps reporting each one until the implementations are
fixed, and the corpus generator leaves the diverging cases out of `conformance/fuzz/`.

Check open findings against the current build (exit 1 while any still reproduces):

```sh
npm run differential -- --replay sim/findings
```

When a finding is fixed: move its bytes to `conformance/travelers/` as vectors for the
rule that was decided, delete them here, run `npm run corpus` (the cases it kept out
can now be frozen), and move its write-up below.

## Open

None. `npm run differential -- --seeds 20000` reports no findings.

## Fixed

### F1 — the 8 KiB blob cap was measured on each side's own re-rendering of the numbers

**Fixed.** The cap is now defined on the one serialization both implementations already
have to produce byte for byte: a free-form object must have a canonical form (every
number in it is a canonical number), and that form is at most 8,192 bytes of UTF-8
(`docs/SPEC.md`, parsing rule 12; `schema.ts` `jsonBlob`; `validate.rs` `json_blob`).
The two reproducers below are now conformance vectors, under the verdict both sides
give: `conformance/travelers/l0-blob-numbers-respelled.json` (accepted: 7,333 canonical
bytes) and `conformance/travelers/reject/blob-number-1e20.json` (refused: `1e20` has no
canonical form). What follows is the finding as it was written up while open.

Found on `2095f22` (the first run of the byte-level fuzzer). One root cause, two
directions, so two files:

| file (then, in this directory) | bytes | SHA-384 of the bytes |
|---|---|---|
| `blob-cap-ts-accepts-rust-refuses.json` | 2,373 | `af349d139fddba889ba39172a410291156194a10c4a588af082c23f2f893b3ea10d2687ae3199065a9b3097c2988fafe` |
| `blob-cap-ts-refuses-rust-accepts.json` | 2,083 | `3e667b385b30fe93f86acfb2cb919cfb5e76bc561d8b6d3c27b4ab1b5d7c7a77a1e00128ad47f0e335c4acd8451f9b4a` |

Both are the smallest valid L0 traveler with one extra member:

```
{"spec":"sje/0.1.0","traveler_id":"tvl_aaaaaa","revision":1,"created_at":"2026-01-01T00:00:00Z",
 "buyer":{"name":"B"},"part":{"family":"F","part_number":"P","material":{"spec":"M"},"qty":{"target":1}},
 "as_built":{"":[1e15,1e15, … 431 times … ]}}        ← first file
 "as_built":{"":[1e20,1e20, … 373 times … ]}}        ← second file
```

(no whitespace or trailing newline in the files; shown wrapped here).

#### Verdicts before the fix

| | TypeScript `parseTravelerJson(bytes)` | Rust `envelope check` |
|---|---|---|
| `…ts-accepts-rust-refuses.json` | **accept** — hash `sha384:bd4d4028…27170`, level `L0`, bound `[]` | **refuse** (`as_built exceeds 8 KiB`) |
| `…ts-refuses-rust-accepts.json` | **refuse** (`as_built: object exceeds 8 KiB`) | **accept** — same hash, level `L0`, bound `[]` |

With one array element fewer in either file (430, 372) the two agree, so these are
minimal for their element; the 8,192 threshold itself is the floor on the size.

#### Diagnosis

Both implementations cap a free-form blob (`as_built`, `quotes[].assumptions`,
`quotes[].capacity`) at 8,192 UTF-16 units — but neither measures the text that was
sent. Each parses the blob, serializes the parsed value again with its own JSON
writer, and measures *that*:

- TypeScript — `src/lib/traveler/schema.ts:41`:
  `z.record(…).refine((v) => JSON.stringify(v).length <= 8192)`. Numbers are rendered
  by ECMAScript `Number::toString`.
- Rust — `crates/secure-job-envelope/src/validate.rs:181-187` (`json_blob`):
  `serde_json::to_string(v)` then `utf16_len(&s) > 8192`. The value was built by
  `BlobVisitor` (`src/de.rs:135-145`): a literal with a fraction or an exponent, or
  an integer beyond `u64`, is an `f64`, and serde_json renders an `f64` with its own
  formatter (always a `.0` on an integral value; exponent form from 1e16 up).

The validate.rs comment says the Rust side "counts UTF-16 code units … to match zod's
`JSON.stringify(v).length`". That holds for strings. It does not hold for numbers,
because the two writers spell the same number at different lengths:

| as written | V8 `JSON.stringify` | serde_json 1.0.151 `to_string` |
|---|---|---|
| `1.0` | `1` (1) | `1.0` (3) |
| `-0` | `0` (1) | `-0.0` (4) |
| `1e2` | `100` (3) | `100.0` (5) |
| `1e15` | `1000000000000000` (16) | `1000000000000000.0` (18) |
| `1e16` | `10000000000000000` (17) | `1e+16` (5) |
| `1e20` | `100000000000000000000` (21) | `1e+20` (5) |
| `0.000001` | `0.000001` (8) | `1e-6` (4) |
| `18446744073709551616` | `18446744073709552000` (20) | `1.8446744073709552e+19` (22) |

So for the first file the blob is 2,161 units as written, **7,333** as V8 re-renders
it (under the cap) and **8,195** as serde_json does (over). For the second: 1,871 as
written, **8,212** in V8 (over), **2,244** in serde_json (under).

Two further consequences of measuring a re-rendering:

- The Rust number depends on a dependency's float formatter. serde_json 1.0.151
  writes floats with `zmij` (`1e+20`); earlier releases used `ryu` (`1e20`). The
  accept/refuse boundary of a blob has already moved once with a version bump.
- The cap does not bound the bytes a blob may occupy on the wire in either
  direction (`"\u0041"` is six bytes and one unit; `1e15` is four bytes and sixteen
  or eighteen units).

#### Reach

One wire document, two verdicts — the property the differential exists to rule out.
`assumptions` and `capacity` are written by the *seller*, so a quote can be shaped to
make the traveler that carries it acceptable to desks on one implementation and
refused by the other. No hash, level or bound split was found: blobs sit outside the
quoteable hash, and both sides agree on every blob they both accept.

#### How the fuzzer reached it

Mutation `blob-fill` (mutations-wire.ts): a blob filled to 8,191 / 8,192 / 8,193
units of one kind of content. The string fillers and the plain-integer fillers agree
on both sides; the fillers `n.0`, `exponent` and `minus-zero` diverge one way (16
cases in seeds 1..20000) and `0.000001` and `21-digit-integer` the other (9 cases).
It is the only finding in those 20,000 seeds, and in sweeps of every mutation alone
over other travelers (41,102 further cases).

```sh
npm run differential -- --start 3727 --seeds 1    # blob-fill[exponent 8192 as_built]          ts accepts, rust refuses
npm run differential -- --start 4165 --seeds 1    # blob-fill[21-digit-integer 8193 as_built]  ts refuses, rust accepts
npm run differential -- --only blob-fill --seeds 2000 --quiet
```

The two files here are not those cases but the smallest documents with the same
cause: `1e15` and `1e20` are the spellings with the largest gap per byte written.

#### What was decided

Of the two ways out — measure the blob's bytes as written, or define the cap on one
canonical rendering — the second was taken: the canonical form already exists, is
already pinned byte for byte by shared vectors, and does not depend on how a sender
chose to spell a number or escape a character. Its consequence is that a number with
no canonical form (above 2^53-1, or a fraction below 1e-5) is refused inside a
free-form object, as it is everywhere else in a traveler. A quote's `assumptions` and
`capacity` are inside the quote's content hash, so such a number used to make a quote
that parsed and could never be hashed or awarded.
