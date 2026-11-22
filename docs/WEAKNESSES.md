# Weakness register

What an adversarial review of SJE 0.1 found, what was done about each finding, and —
most important — what is **still true** after the fixes.

The review ran nine independent passes (signatures, envelopes, parse parity between the
two implementations, lifecycle, the browser desk, the MCP server and CLI, supply chain,
documentation against code, and the protocol design itself). Every finding rated HIGH was
reproduced with a runnable proof before it was listed here. Severity is for a real
deployment between companies, not for the demo.

**How to read the status column**

| Status | Meaning |
|---|---|
| **Fixed** | Changed in code, with a test or conformance vector that fails without the fix. The pull request is linked. |
| **In progress** | A fix is written and under review; this row is updated when it merges. |
| **Limit** | A property of the 0.1 design that this version does not change. It is written down so that nobody relies on the opposite. |
| **Decision** | Fixable, but the fix changes what the product *is* (the wire format, the ladder, shipping a signer). It needs a product decision, not a patch. |
| **Owner** | Needs an action only the repository's owner can take (settings, a domain, an account). |

Pull requests: [#26](https://github.com/rivletio/secure-job-envelope/pull/26) supply chain ·
[#27](https://github.com/rivletio/secure-job-envelope/pull/27) parse parity ·
[#28](https://github.com/rivletio/secure-job-envelope/pull/28) strict text boundary ·
[#29](https://github.com/rivletio/secure-job-envelope/pull/29) envelope shape ·
[#30](https://github.com/rivletio/secure-job-envelope/pull/30) verification ·
[#31](https://github.com/rivletio/secure-job-envelope/pull/31) receive policy ·
[#32](https://github.com/rivletio/secure-job-envelope/pull/32) desk receive path.

---

## Read this first: what is still true

These are not bugs waiting for a patch. They are the edges of what 0.1 is.

1. **Nothing that ships can sign.** The desk and the MCP server verify signatures; neither
   can make one. Every traveler, quote and award produced with the shipped tools is
   therefore *unsigned*, and an unsigned award looks exactly like a forged one. The
   receive path now says so and asks for an explicit acknowledgment — but the control
   that actually protects a ship-to address is **confirming an award with the buyer
   through a channel you already trust**. (W-51)
2. **A "verified" signature names an org id, not a company.** Any org enrolled in the
   directory can author a traveler under its own id and any display name, and it
   verifies — as that org. Read the org id; a name on the page is whatever its author
   typed. (W-03)
3. **Whoever runs the trust root can impersonate anyone under it,** and can read what is
   sealed to anyone under it, by issuing a directory with an extra entry. Nothing in the
   format detects that. (W-50)
4. **A signature proves authorship at the moment you check it, not for the record.** There
   is no signing time. When a key is revoked or expires, earlier honest signatures stop
   verifying; a stolen key can backdate. Keep the document, the directory and the time
   together if you need evidence later. (W-49)
5. **The buyer signs the part, the award and the ship-to — and nothing else.** Ops,
   as-built data, which quotes are attached, and drawings are outside every signature.
   (W-52)
6. **An envelope hides content, not traffic, and says nothing about its sender.** Anyone
   with your public key can seal to you. Recipient pseudonyms, recipient count and sizes
   are visible. (W-35, W-36)
7. **Forward secrecy has conditions.** The one-time key is deleted when a traveler is
   admitted, not when it is decrypted; two senders can pick the same one-time key and the
   second message is then lost; a recipient cannot refuse a non-forward-secret envelope.
   (W-31, W-32)
8. **The desk is a page on a shared origin, holding plaintext working data in browser
   storage.** It is not a system of record and not a CUI system. (W-40)

---

## A. Authenticity was not enforced where documents are received

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-01 | High | **A forged, unsigned award was accepted on every receive path.** Verification existed only as library functions. Anyone holding the public directory and a traveler id could seal an award with their own ship-to to the winning seller: the desk stored it and showed the job as executable; the buyer's genuine award arriving later was refused as "locked". | **Fixed** for the desk and CLI ([#30](https://github.com/rivletio/secure-job-envelope/pull/30), [#31](https://github.com/rivletio/secure-job-envelope/pull/31), [#32](https://github.com/rivletio/secure-job-envelope/pull/32)): a signature that is present and fails is refused; an unsigned award needs an explicit per-statement acknowledgment; an award verified as the buyer's replaces an unverified one. `envelope verify` exits 0 only for a verified traveler. **In progress** for MCP. Tests: `import-policy.test.ts`, `store-import.test.ts`, `tests/cli.rs`. |
| W-02 | High | **A copy with the same id replaced the held traveler wholesale** — no comparison of revision, content or signatures. It rolled back an amendment, swapped the part under an unchanged revision number, wiped other sellers' quotes, stripped the ITAR flag. | **Fixed** ([#31](https://github.com/rivletio/secure-job-envelope/pull/31), [#32](https://github.com/rivletio/secure-job-envelope/pull/32)): older revision refused; same revision with different content refused; quotes merged by id, never dropped. MCP is stateless and cannot hold a copy to compare (see W-05). |
| W-03 | High | **"Verified" meant "some enrolled org signed it".** The signer was compared with the document's own `buyer.org_id`, and the page showed only self-asserted names. An enrolled losing bidder could re-issue a traveler under its own org id with the buyer's display name: author verified, award verified, ship-to redirected. | **Fixed** in part ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)–[#32](https://github.com/rivletio/secure-job-envelope/pull/32)): the buyer org of a held traveler can never change; import notes name the signing org id; the spec states what a passed check does not mean, with a conformance case (`reissued-under-another-org`). The panel now shows the directory's org id and key id as the identity of every passed check, and the document's own name after it, labelled as self-asserted ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)). **Limit:** on *first* receipt there is nothing to compare with — the reader must check the org id. |
| W-04 | High | **The MCP server took the trust root from tool arguments.** A note injected into an agent's context could supply an attacker's root and directory binding the real recipient to the attacker's key; sealing succeeded indistinguishably. | **In progress** (operator-pinned root). |
| W-05 | High | **MCP buyer tools awarded whatever body the counterparty returned.** The server is stateless: a seller could change material, tolerance or quantity, quote against that, and the buyer agent's evaluate → award reported "bound". | **In progress** (`expected_traveler_hash`, required on award). |
| W-06 | Medium | **The demo trust anchor looks like a real one.** Its root, signing and encryption secrets are public constants; one click loads and persists it; nothing afterwards said "demo". | **Fixed** ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): the demo root is recognized by its key, however it is loaded; loading it needs confirmation; a standing banner marks it; every check that passes under it is shown as a warning that proves nothing, never a success; sealing under it needs a tick per envelope. Described in `GOVERNANCE.md`. |
| W-07 | Medium | **Trust-anchor handling.** An older directory silently replaced a newer one (a revoked key authenticated again); a different root silently replaced the held one; the root was shown as 5,184 hex characters with no fingerprint, so comparing it out of band was impractical. | **Fixed** ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): a root is shown as a 32-digit fingerprint; a first root, or a change of root, loads only when that fingerprint is confirmed; a directory older than one already accepted under the same root is refused, and the desk remembers the newest it has accepted per root. **Limit:** that memory lives in browser storage — clear it and the desk cannot tell whether a directory is the newest; two directories with the same issue time are both accepted. |
| W-08 | Medium | **CLI.** An unknown command exited 0 (`envelope verify f && echo TRUSTED` printed TRUSTED — there was no `verify`); input was read without a bound; error text echoed control characters from the document. | **Fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27), [#30](https://github.com/rivletio/secure-job-envelope/pull/30)). Tests: `tests/cli.rs`. |
| W-09 | Low | **The ITAR "directory attestation" gate trusted a self-declared `seller.org_id`** (an unsigned quote naming an attested org passed), failed open in Rust on a malformed traveler, and had no shipped caller. | Gate **fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)): the quote must be signed by the seller it names; 12 shared cases. Enforcing it when sealing: **in progress**. It remains a consistency rule, not export control. |

## B. One wire document, two verdicts (TypeScript vs Rust)

The premise of the format is that two independent implementations judge the same bytes
identically. Each row below was a document one accepted and the other refused — or that
both accepted while reading it differently.

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-10 | High | **Rust accepted any structure written as a positional JSON array**; TypeScript refused. Rust's verifier read the raw JSON by key while the typed view differed, so a positional quote placed before the awarded one made Rust report a valid award over a different price. | **Fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)). Vectors `positional-struct-*`. |
| W-11 | High | **The TypeScript schema silently dropped a member named `__proto__`**; Rust kept it. The two verified different bytes for one document — the signer could choose which implementation accepted it. | **Fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)): refused by both. Vectors `*-proto-member*`. |
| W-12 | High | **Duplicate `quote_id`.** The desk showed the bound $14.20 quote; the award took the *first* quote with that id — a hidden twin at $1,420 — and the buyer-signed award verified on both sides. | **Fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)): ids unique (also price lines per quantity, op sequence numbers). |
| W-13 | Medium | Rust never validated `award.sig` (algorithm, key id, hex, length). | **Fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)). Vectors `award-sig-*`. |
| W-14 | Low | A name made only of U+0085 was Draft in Rust and quoteable in TypeScript (different definitions of whitespace). | **Fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)). Vector `l0-nel-name.json`. |
| W-15 | Low | **Size-cap units.** Rust capped UTF-8 bytes; TypeScript capped UTF-16 units of a re-serialization. A CJK traveler up to ~1.5 MB passed TypeScript and failed Rust, and could not be re-imported from its own archive. | **Fixed** ([#28](https://github.com/rivletio/secure-job-envelope/pull/28)): bytes of the wire text on both. |
| W-16 | Low | A UTF-8 byte-order mark was accepted by the TypeScript import and refused by Rust; the archive digest was computed over decoded text, not bytes. | **Fixed** ([#28](https://github.com/rivletio/secure-job-envelope/pull/28), envelopes [#29](https://github.com/rivletio/secure-job-envelope/pull/29), directories [#30](https://github.com/rivletio/secure-job-envelope/pull/30)). |
| W-17 | Low | **Repeated member names.** Rust refused a repeated typed key; `JSON.parse` kept the last and never examined the others, so a value hidden behind a duplicate bypassed every TypeScript check. The claims register had called this "not exploitable". | **Fixed** ([#28](https://github.com/rivletio/secure-job-envelope/pull/28)): both refuse a repeated name at any depth. Vectors `duplicate-member-*`. |
| W-18 | Medium | **The 8 KiB cap on free-form blobs was measured on each implementation's own serialization**, and the two write numbers at different lengths: a blob of 431 numbers written `1e15` was accepted by TypeScript and refused by Rust; 373 written `1e20`, the reverse. A quote's blobs are written by the seller, so a quote could be shaped to be valid on one implementation only. The audit measured it by hand, and this register first rated it Low and called it a decision; the byte-level fuzzer then found it unaided in its first run. Related: a number with no canonical form inside a quote's blob made a quote that parsed and could never be hashed or awarded. | **Fixed** ([#37](https://github.com/rivletio/secure-job-envelope/pull/37)): a blob must have a canonical form, of at most 8,192 bytes of UTF-8 — the one serialization both sides already produce byte for byte. Seven shared vectors, the fuzzer's two reproducers among them. **This changes what is accepted:** a blob holding a number above 2^53−1 or a fraction below 1e-5 is now refused (write such a value as a string), and the cap counts bytes, not UTF-16 units. |
| W-19 | Low | The TypeScript envelope opener accepted what Rust refused: 16- and 24-byte content keys under an "AES-256-GCM" label, nonces of any length, unknown members. | **Fixed** ([#29](https://github.com/rivletio/secure-job-envelope/pull/29)): one exact shape; 48 shared cases. |
| W-20 | Low | **The directory was signature-checked but never shape-checked.** `entries:[null]` threw in TypeScript; `capabilities.itar:"false"` granted ITAR; one key id on two orgs meant the first listed won; the key to encrypt to depended on entry order. | **Fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)): exact shape before any signature is believed; order-independent selection. 58 shared cases. |
| W-21 | Medium | **Award verification and level 2 were structural.** A verified award could name a quote made against another revision, or have no price at the awarded quantity; level 2 holds for an award over an expired quote. | Verification **fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)): the awarded quote must be present, unchanged, bound to this revision and priced at the awarded quantity. **Decision:** the level ladder is still structural (level 2 says the fields are there, not that the award is sound), and a seller-signed quote is not required. |
| W-22 | Medium | **The tests did not pin the claims.** With the signer-org check, revocation and the quote-hash requirement deleted, every Rust test passed; four archive guards could be deleted with everything green; some reject vectors failed for an unrelated reason; the fuzzer could not generate any class in this section. | **Fixed** progressively ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)–[#31](https://github.com/rivletio/secure-job-envelope/pull/31)): every reject vector's reason is pinned per implementation; one test per archive guard; verification cases carry the refusal reason; 33 + 18 single-rule mutations each fail a test. Canonical vectors now carry the JSON *text* where the spelling is the test (`-0`, `10.0`, `1e2`; 114 cases, each refusal pinned per implementation), and assertions that passed for an unrelated reason are pinned to their rule ([#36](https://github.com/rivletio/secure-job-envelope/pull/36)). The differential fuzzer now judges exact wire bytes on both sides, with 175 mutations; run against the code before each fix it finds every class in this section, and at this commit none in 20,000 cases ([#37](https://github.com/rivletio/secure-job-envelope/pull/37)). |
| W-23 | Medium | **The published JSON Schema was stale**: it rejected every signed or hash-bound award, and a schema-driven sanitizer would strip the signature; it passed 18 of 43 reject vectors. | **Fixed** ([#36](https://github.com/rivletio/secure-job-envelope/pull/36)): the schemas are held to the implementation field for field, on every vector, and on 9,964 single-edit probes. **Limit:** twelve rules cannot be stated in a JSON Schema (wire text, comparisons between members, uniqueness by one member, serialized size); they are listed with reasons in `public/schemas/not-expressible-0.1.0.json`. A validator that stops at the schemas accepts documents a conforming implementation refuses. |

## C. Lifecycle and business logic

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-24 | Medium | **An award commits to quote content the buyer was never shown** (exception price deltas, freight, assumptions, expiry). Form parsing: "1,250.00" silently dropped the price line, "0.004" stored 0, a target quantity of "5,000" stored 1. | **Fixed.** Duplicate price lines refused ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)). Every term an award commits to is shown before awarding, with a total at the award quantity; numeric inputs are stored exactly as typed or refused with the reason ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)). **Limit:** the basis of an exception's `price_delta` is undefined — see W-62. |
| W-25 | Medium | A seller could not re-quote after an amendment (the one-quote rule counted stale quotes); a 65th quote was accepted and the traveler then silently vanished on reload. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)): only quotes bound to the current revision, and still live, hold a seller's slot; the store re-validates before it keeps a traveler. **Limit:** a quote's `seller.org_id` is self-asserted unless signed, so a party able to add quotes to a buyer's copy can still crowd it (64 quotes shared by all sellers). |
| W-26 | Low | Two definitions of "locked": an award naming no bound quote was level 1 yet locked. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)): locked means exactly "level 2 or above", in one function that the store, the MCP tools and the desk all call; an award naming no bound quote is reported as void. **Limit:** MCP's lock is derived from the document it is handed — delete `award` and an amendment succeeds; the party holding the authoritative copy is responsible for it. |
| W-27 | Low | The award dialog pre-filled ship-to and ops from an imported file; the desk could not delete a traveler. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)): nothing is pre-filled from the file — what it carries is shown apart, labelled unsigned, and copied in only on request; a traveler can be deleted, and the deletion is logged with the hash of what was removed. See also W-58. |
| W-28 | Low | Two tabs: the last writer replaced the whole store, so a stale tab reverted a locked traveler. | **Fixed** ([#32](https://github.com/rivletio/secure-job-envelope/pull/32)). |
| W-29 | Info | The "append-only" audit log is a ring of the last 100 events in the same editable browser storage as the travelers; refusals are not logged. | **Limit.** It is a convenience, not an audit trail. |

## D. Confidentiality and key lifecycle

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-30 | High | **No bid confidentiality between sellers.** The whole traveler was the unit of exchange: a re-sent RFQ handed seller B seller A's price, the winner's file carried every losing bid, and a loser learned who won and where it ships. | Rule **written and tested** ([#32](https://github.com/rivletio/secure-job-envelope/pull/32), `projection.ts`). Applied automatically when sealing: **in progress**. |
| W-31 | Medium | **Forward-secret mode silently lost messages.** A sender picked a one-time key at random with no memory: one honest sender sealing 20 travelers to an 8-key bundle left most permanently unopenable, each reported "forward-secret". | **Fixed** for one sender ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): a seal reports which one-time key it used, a sender passes back the ones it has used and is never given one twice, and when they are all used the seal says so and falls back (or refuses, if forward secrecy was required). The desk keeps that list per recipient. **Limit:** the list is per browser profile; two *different* senders can still collide, and anyone can spend a published pool; only a coordinating service could prevent that, and the format has none. |
| W-32 | Medium | **Deletion of a used one-time key was weaker than documented.** The docs said "deleted before the secret is used"; the code decrypted first. The key was spent before the import decision, so a refusal lost the envelope; a failed write was silent; two tabs or two server processes resurrected spent keys. | Two-phase open **fixed** ([#31](https://github.com/rivletio/secure-job-envelope/pull/31), [#32](https://github.com/rivletio/secure-job-envelope/pull/32)): spent only once the traveler is admitted; a failed deletion is reported; documents corrected. Remainder **fixed** ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): the deletion is stored *before* the key is forgotten in memory, so a failed write changes nothing and can be retried; the desk reads every keystore write back and shows a standing "not saved" alert if the browser did not keep it; a tab whose keystore was changed by another tab locks itself and says why; the MCP server writes the file 0600 with compare-and-swap and re-reads it when another process changed it. **Limit:** copies this software does not control keep the key — a backup, browser sync, an older blob restored later (the blob carries no counter); two server processes can still pass the comparison in the same instant. |
| W-33 | Low | Keystore key-derivation parameters were read from the file without bounds (unlock could be made to hang); the org id in the header was not authenticated. | **Fixed** ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): the blob's shape and cost parameters are checked before any key derivation (cost between 2^15 and 2^20, nothing else accepted), every failure is the one uniform error, and the whole clear header is authenticated. **This is a new at-rest format** (`sje-keystore/0.2.0`): older keystores still unlock and are rewritten in the new format on the next save; a build from before this change cannot open a rewritten one. No wire format changed. |
| W-34 | Medium | MCP `sje_identity` took the passphrase as an argument and returned the keystore — both halves in one transcript. | **In progress**. |
| W-35 | Info | AES-GCM is not key-committing (recipients of one multi-recipient envelope are not guaranteed to read the same payload); recipient ids are 64-bit truncated hashes. | **Limit.** Stated in `ENVELOPE-DRAFT.md`; compare `traveler_hash`. |
| W-36 | Low | Envelope metadata: a stable recipient pseudonym resolvable by any directory holder, the recipient count, the version, the one-time key id and unpadded sizes are visible. | **Limit.** |

## E. MCP surface

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-37 | Medium | Tool results replayed counterparty text unlabelled; unknown arguments were ignored, so a misspelled `require_forward_secrecy: true` silently sent without forward secrecy; errors echoed attacker-chosen text. | **In progress**. Archive errors no longer echo member names ([#28](https://github.com/rivletio/secure-job-envelope/pull/28)). |
| W-38 | Medium | A 5.6 KB envelope cost about 1 GiB and two seconds per open (an issue object was built per array element before the length cap applied). | **Fixed** ([#26](https://github.com/rivletio/secure-job-envelope/pull/26) dependency upgrade; [#28](https://github.com/rivletio/secure-job-envelope/pull/28) a structural pre-check that does not depend on the dependency). Size caps on object arguments: **in progress**. |
| W-39 | Low | `sje_seal` capped the directory argument at the *traveler's* 512 KiB (about 60 orgs) — a regression from an earlier hardening pass. | **Fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)). |

## F. Web deployment

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-40 | Medium | **The desk shares an origin** with the demo site and with every other site published under the same host. Browser storage (plaintext travelers, the encrypted keystore, the trust anchor) and an unlocked desk's memory are reachable from any page on that origin. | **Owner** (serve the desk from an origin of its own). Until then: **Limit** — a script-injection flaw anywhere on the origin is one on the desk. |
| W-41 | Low | No Content-Security-Policy; a third-party stylesheet loaded on the page where the passphrase is typed. | **Fixed** ([#35](https://github.com/rivletio/secure-job-envelope/pull/35)): fonts are served from the same origin; every published document carries a policy that denies by default, allows this origin only, runs no inline script the build did not hash, and allows no inline style, no `eval` and no network call; the build refuses to publish a document that would break it. **Limits:** the policy travels in a `<meta>` element, which cannot forbid framing or report violations (both need response headers); it is written into the Pages output only, so a self-hosted build must send it as a header; checked in Chromium only. |
| W-42 | Low | The demo site's service worker controlled the desk's path: a desk fix would reach returning visitors one visit late. | **Fixed** ([#35](https://github.com/rivletio/secure-job-envelope/pull/35)): the worker answers only for the demo site's own files; the desk always comes from the network and is never cached; the old cache is removed on activation. **Limit:** the worker's scope still covers the desk's path (a scope is a URL prefix), and the host caches pages for ten minutes. |
| W-43 | Info | An unused `innerHTML` path in the demo site's DOM helper. | **Fixed** ([#35](https://github.com/rivletio/secure-job-envelope/pull/35)); a test fails if a markup sink reappears in the demo site's sources. |

## G. Supply chain and process

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-44 | High | **`main` is unprotected, and the site deployed in parallel with CI** — the desk went live before its tests finished. | Deploy now runs only after CI succeeds on `main`, with a least-privilege token: **fixed** ([#26](https://github.com/rivletio/secure-job-envelope/pull/26)). Branch protection (required checks, no direct pushes): **Owner**. |
| W-45 | Medium | A real advisory (non-constant-time masking in a dependency under the post-quantum primitives) had been printed and ignored on every run: the audit job could not fail. No advisory coverage for JavaScript (23 open). | **Fixed** ([#26](https://github.com/rivletio/secure-job-envelope/pull/26)): both lockfiles clean; advisories block and run weekly. |
| W-46 | Medium | The crate's homepage and the JSON Schemas' `$id` point at a domain the review found unregistered, and the package name is unclaimed on the public registries — whoever registers them first speaks for the project. | **Owner.** |
| W-47 | Low | Deploy token scope too broad; no `--locked`; static builds never ran on pull requests; no ignore patterns for keystores and envelopes; actions referenced by mutable tags. | **Fixed** ([#26](https://github.com/rivletio/secure-job-envelope/pull/26)) except pinning actions to commit hashes: **Owner** (or an update bot). |
| W-48 | Info | The post-quantum libraries are pre-1.0 and unaudited; signing is deterministic ML-DSA; there is no classical hybrid. | **Limit.** Algorithm selection is not certification. |

## H. Protocol design limits

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-49 | High | **No signing time, no trusted time, no revocation timestamp.** Verification uses the verifier's clock. After a key is revoked or expires, earlier honest signatures stop verifying; a stolen key backdates freely under any directory still in its window. | **Limit.** A signature here authenticates at receipt; it is not durable evidence. |
| W-50 | High | **The trust root is all-powerful and unaccountable.** No versioning, transparency or key continuity. It can add a second entry for any org and sign as it, or a newer encryption key and read what is sealed to it. `GOVERNANCE.md` said the root "cannot by itself produce a valid buyer award signature" — false. | **Limit**; document corrected. The desk now refuses an older directory and asks for a root change to be confirmed against a fingerprint (W-07) — which makes a substitution harder to do unnoticed, and does nothing about what the root itself may issue. |
| W-51 | Medium | **Unsigned is a first-class state at every level, and no shipped surface can sign.** | **Decision** (ship a signer; a strict profile that refuses unsigned documents). The receive path now treats unsigned as unverified, never as fine. |
| W-52 | Medium | **Outside every signature:** ops (written by the buyer at award), as-built data, which quotes are attached, drawings. There is no acknowledgment message; a buyer can issue two valid awards for one traveler. | **Limit** (changing what is signed changes the format). |
| W-53 | Medium | **No freshness, sequence or audience binding.** Old signed documents replay; anyone can re-seal a signed RFQ to anyone. | Replay over a copy you hold is **fixed** ([#31](https://github.com/rivletio/secure-job-envelope/pull/31), [#32](https://github.com/rivletio/secure-job-envelope/pull/32): an older revision is refused). **Limit:** a first-time recipient cannot tell a current document from a superseded one. |
| W-54 | — | **Documentation.** 26 of 48 claim rows were overstated, stale, or unsupported by the test they cited; the spec did not define the signed bytes, the envelope's key derivation, the directory format, units, or the parse rules a third implementation needs. | **Fixed** in part: SPEC §Parsing ([#27](https://github.com/rivletio/secure-job-envelope/pull/27), [#28](https://github.com/rivletio/secure-job-envelope/pull/28)), envelope wire shape ([#29](https://github.com/rivletio/secure-job-envelope/pull/29)) and key derivation, signatures / directory / verification ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)). Remaining corrections: **in progress**. |

## Found while fixing

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-55 | Medium | **Archive members.** The path-traversal guard checked a name the zip library had already normalized, so `../traveler.json` imported cleanly (the test for it passed only because its archive lacked another file). Two members with the same name were silently collapsed to one, while another unzip tool might extract the other. | **Fixed** ([#28](https://github.com/rivletio/secure-job-envelope/pull/28)): stored names checked, fail-closed; duplicate or unlisted members refused. **Limit:** bytes present in the file but absent from its central directory are not examined. |
| W-56 | Low | **The development server was broken** — every request answered 500 — and nobody knew, because CI built the production bundles but never started it. Contributors verifying a change in a browser were not looking at the code they thought. | **Fixed** ([#32](https://github.com/rivletio/secure-job-envelope/pull/32)): path resolution enabled; a smoke test starts the dev server in CI. |
| W-57 | Low | Two "is it signed?" checks used "every signature check passes", which is true for a traveler with no signatures at all. | **Fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)). |
| W-58 | Medium | **An unsigned ship-to could ride a returned file into the buyer's own copy.** On import, a ship-to or ops list that arrived without an award was merged into the held traveler as a "draft". A seller returning a quote could put its own address there; it then sat in the buyer's copy and was offered back as the default when the buyer awarded. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)): a ship-to or ops list without an award is never merged in; the import says it was not taken. |
| W-59 | Low | **A failed save was silent.** When the browser refused a write (storage full or blocked) the desk dropped it and went on looking saved; the next reload lost the work. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)): a standing warning is shown until a write succeeds. **Limit:** the desk has nowhere else to save — export what you need. |
| W-60 | Low | **Dates were shifted by the viewer's time zone.** A need-by of 30 October read "29 Oct" to anyone west of UTC, so two people looking at one traveler saw two different dates. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)): the day shown is the day written. |
| W-61 | Low | An expired quote kept its seller's one-quote slot, shutting the seller out of the revision for good; the store accepted an award for a quantity the quote does not price; state restored from browser storage (role, selected seller) was spread into the store unchecked. | **Fixed** ([#34](https://github.com/rivletio/secure-job-envelope/pull/34)). |
| W-62 | Low | **The basis of an exception's `price_delta` is undefined** — per unit or for the order. Two parties can read one quote, with one hash, as two totals. | **Decision.** The desk counts each delta once, shows it on its own line and says the basis is undefined. `SPEC.md` now states that 0.1 does not define it and that a per-unit change belongs in the price lines. Recommended for the next version: define it as an amount for the order. |
| W-63 | Low | **The parser that was tested was not the parser that shipped.** The schema library compiles its parsers with `new Function` where the runtime allows it and interprets them where it does not. Under a strict policy the browser ran the interpreter; Node — every test, the MCP server, the fuzzer — ran the compiled path. | **Fixed** ([#35](https://github.com/rivletio/secure-job-envelope/pull/35)): the interpreter is selected in every runtime, and a test fails if the library compiles any code from a string. |
| W-64 | Info | The desk's favicon and the spec page's JSON Schema links pointed outside the published site (root-absolute paths under a sub-path deployment). | **Fixed** ([#35](https://github.com/rivletio/secure-job-envelope/pull/35)); the Pages build now fails on a reference to a file that is not in the output. |
| W-65 | Info | The disclosure map — "every field classified" — did not classify `award.quote_hash` or `award.sig`: its test enumerated the published schema, which did not list them. | **Fixed** ([#36](https://github.com/rivletio/secure-job-envelope/pull/36)): both are classified, and the test enumerates the published schema and the implementation's own. |
| W-66 | Low | **A claim the tests did not support.** The claims register said empty strings are "dropped" from the hashed body; the tests it cited contain only empty arrays. Both parsers in fact refuse an empty string in every typed position, so nothing is dropped. Several other assertions passed for an unrelated reason (a fixture hash of the wrong length made three price tests vacuous). | **Fixed** ([#36](https://github.com/rivletio/secure-job-envelope/pull/36)): the claim is reworded and the assertions are pinned to their rule. |
| W-67 | Low | **One nesting limit in the parser, another in the canonicalizer.** Both canonicalizers allowed 129 nested containers; one parser stops at 127 and the other has no limit. A value nested 128 deep, read with a plain `JSON.parse`, canonicalized — and so could be signed and verified — in TypeScript, and could not be read by Rust. Travelers were not affected (their parser applies the limit). | **Fixed** ([#37](https://github.com/rivletio/secure-job-envelope/pull/37)): 127 in both canonicalizers, the same number as the parsers; stated in the spec; pinned by shared text vectors. |
| W-68 | Low | **The fuzzer's own base documents were sometimes invalid.** About one generated traveler in a few hundred priced the same quantity twice, which the format has refused since duplicate price lines were closed. A mutated case built on such a document is refused whatever its mutation did, so it tested nothing — silently. | **Fixed** ([#37](https://github.com/rivletio/secure-job-envelope/pull/37)): generated price lines are distinct, and an unmutated case that is refused is itself reported as a finding. |
| W-69 | Info | For a traveler built in memory and never parsed, Rust hashed whatever `spec` the value carried and TypeScript hashed the constant. No parsed traveler was affected. | **Fixed** ([#37](https://github.com/rivletio/secure-job-envelope/pull/37)): both hash the constant. |
| W-70 | Medium | **Verifying one traveler re-verified the whole key directory once per signature.** Whoever sends a traveler chooses how many quote "signatures" ride on it, and each check canonicalized and hashed the directory again: 66 times for 64 quotes. Measured on a 28 KB traveler against a 512-entry directory: 15 seconds to report on it, 27 seconds to run the ITAR gate over its quotes. | **Fixed** ([#38](https://github.com/rivletio/secure-job-envelope/pull/38)): the directory is established once per report or gate, however many signatures follow; a test counts the verifications. (The Rust core already worked this way.) |
| W-71 | Low | **A refusal repeated the document at length.** An unknown member's name was copied into the error in full — 500 KiB of it if the sender liked — and from there into a log, a toast, or an agent's context, where it reads as the software's own words. | **Fixed** ([#38](https://github.com/rivletio/secure-job-envelope/pull/38)): a name the document's author chose is quoted, cut at 40 characters and kept on one line, with characters that hide or reorder text masked; a long path is shortened. **Limit:** up to 40 characters of the author's text still appear, quoted. |
| W-72 | Low | The award guard asked for a price at the *target* quantity whatever quantity was being awarded: it refused a priced break quantity when the target was not quoted, and said nothing about the quantity actually awarded. | **Fixed** ([#38](https://github.com/rivletio/secure-job-envelope/pull/38)): the guard checks the quantity the award is for — the rule verification applies to a signed award. |
| W-73 | Medium | **Text from a document could rewrite what the desk appeared to say.** Names, part fields, notes and addresses were drawn as written. A buyer name carrying a right-to-left override read "Northline Equipment VERIFIED" in the page header and on the card; a zero-width character makes two different names look the same. | **Fixed** ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): every string taken from a document is drawn with characters that are not themselves drawn — controls, direction overrides, zero-width and other ignorable characters — replaced by a placeholder naming them, each in its own direction-isolated span. **Limit:** look-alike letters from another script pass through; a name is never evidence. |
| W-74 | Low | **A failed save left the session and the stored keystore disagreeing.** Spending a one-time key deleted it in memory first and stored the result second; when the store failed the session had lost a key the stored blob still had, and trying again did nothing. | **Fixed** ([#39](https://github.com/rivletio/secure-job-envelope/pull/39)): stored first, forgotten second; a failed store changes nothing and can be retried. |
| W-75 | Low | **Tests that asserted only "refused".** In the envelope, store and Rust unit tests, and in one example, a refusal was asserted without its reason — `assert.throws(fn)`, `.is_err()`, or a string passed where a matcher was meant (`assert.rejects` takes it as the failure message) — so the test passed whichever rule did the refusing. Several were refused for a different reason than the test said: a malformed recipient entry stopped at the shape check and never reached the recipient-set authentication the test was named for; the example's "a flipped byte is refused (AEAD)" step ran on an envelope whose one-time key was already spent, and never reached the AEAD; a duplicate-name case had lost its escape and was a second copy of the case before it. And no shared case touched the two ciphertexts of a forward-secret recipient: the check on either could be deleted from either implementation and every test still passed. | **Fixed** ([#40](https://github.com/rivletio/secure-job-envelope/pull/40)): each refusal is compared with its reason and has a control beside it (the same input without the one defect is accepted); four shared cases hold each ciphertext member to its form. Of 79 mutants written against these tests, 19 were invisible to the tests as they stood; 76 are now caught, and the three that survive are a pair of redundant guards (caught when both are removed) and one branch no value can reach. The same pattern remains in `tests/vectors.rs` and the `sign.rs` unit tests, where the expected verdict comes from the shared case files. |

---

## How the fixes were checked

- **Shared vectors, both implementations.** Reject vectors carry the reason each
  implementation must give (`conformance/travelers/reject-reasons.json`); envelope cases
  carry the stage that must refuse (`envelope-cases.json`); verification cases carry the
  refusal reason (`verify-cases.json`, `directory-cases.json`). The generator states each
  case's required outcome and fails if the TypeScript implementation disagrees; the Rust
  runner then checks the same files independently.
- **Mutation.** For each security rule, the rule was deleted and a test had to fail: 8
  mutations for the envelope shape, 33 for verification, 18 for the receive policy, 42
  for the published schemas and their rules file. One survivor was found this way and
  closed.
- **Bytes, not objects.** Travelers, envelopes and directories are parsed from the bytes
  as received wherever they cross a company boundary; the vectors are replayed from bytes.
- **A fuzzer that is itself tested.** The differential fuzzer hands the same bytes to
  both implementations. It was run against the code as it stood before each parity fix
  and had to find that class of divergence — it found all of them — and its first run on
  current code reported one more that was still open (W-18). It compares travelers only.
- **A browser.** The desk was driven in Chromium. Receive path: forged award, rollback,
  body swap, buyer change, two tabs. Keys: a first trust root needs its fingerprint
  confirmed, an older directory is refused with no way to load it anyway, a
  forward-secret envelope opens once and its key deletion is stored, a second tab
  changing the keystore locks the first, and a name carrying a direction override is
  shown with the override spelled out. Award dialog: nothing pre-filled, a planted ship-to
  shown apart and used only on request. Storage: the warning appears on a failed write
  and clears when one succeeds. Published pages: the built output was served the way
  the host serves it and exercised end to end — no policy violation, no request to
  another origin, nothing of the desk in the service worker's cache.
- **Not checked by anything here:** the cryptographic libraries themselves, side channels,
  the browser, the host the desk is served from, or any party's operational handling of
  keys.
