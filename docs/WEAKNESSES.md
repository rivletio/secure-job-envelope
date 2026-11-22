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
| W-03 | High | **"Verified" meant "some enrolled org signed it".** The signer was compared with the document's own `buyer.org_id`, and the page showed only self-asserted names. An enrolled losing bidder could re-issue a traveler under its own org id with the buyer's display name: author verified, award verified, ship-to redirected. | **Fixed** in part ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)–[#32](https://github.com/rivletio/secure-job-envelope/pull/32)): the buyer org of a held traveler can never change; import notes name the signing org id; the spec states what a passed check does not mean, with a conformance case (`reissued-under-another-org`). Showing the org id as the primary identity in the panel: **in progress**. **Limit:** on *first* receipt there is nothing to compare with — the reader must check the org id. |
| W-04 | High | **The MCP server took the trust root from tool arguments.** A note injected into an agent's context could supply an attacker's root and directory binding the real recipient to the attacker's key; sealing succeeded indistinguishably. | **In progress** (operator-pinned root). |
| W-05 | High | **MCP buyer tools awarded whatever body the counterparty returned.** The server is stateless: a seller could change material, tolerance or quantity, quote against that, and the buyer agent's evaluate → award reported "bound". | **In progress** (`expected_traveler_hash`, required on award). |
| W-06 | Medium | **The demo trust anchor looks like a real one.** Its root, signing and encryption secrets are public constants; one click loads and persists it; nothing afterwards said "demo". | **In progress** (detected by root key; banner; verdicts downgraded). Described in `GOVERNANCE.md`. |
| W-07 | Medium | **Trust-anchor handling.** An older directory silently replaced a newer one (a revoked key authenticated again); a different root silently replaced the held one; the root was shown as 5,184 hex characters with no fingerprint, so comparing it out of band was impractical. | **In progress**. |
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
| W-18 | Low | The 8 KiB cap on free-form blobs is measured on each implementation's own serialization, and the two render some numbers differently (`1e20`, `1.0`), so a blob near the boundary can be accepted by one and refused by the other. No hash or signature is affected. | **Decision** (redefining the bound changes the format). Documented as CLAIMS G10. |
| W-19 | Low | The TypeScript envelope opener accepted what Rust refused: 16- and 24-byte content keys under an "AES-256-GCM" label, nonces of any length, unknown members. | **Fixed** ([#29](https://github.com/rivletio/secure-job-envelope/pull/29)): one exact shape; 48 shared cases. |
| W-20 | Low | **The directory was signature-checked but never shape-checked.** `entries:[null]` threw in TypeScript; `capabilities.itar:"false"` granted ITAR; one key id on two orgs meant the first listed won; the key to encrypt to depended on entry order. | **Fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)): exact shape before any signature is believed; order-independent selection. 58 shared cases. |
| W-21 | Medium | **Award verification and level 2 were structural.** A verified award could name a quote made against another revision, or have no price at the awarded quantity; level 2 holds for an award over an expired quote. | Verification **fixed** ([#30](https://github.com/rivletio/secure-job-envelope/pull/30)): the awarded quote must be present, unchanged, bound to this revision and priced at the awarded quantity. **Decision:** the level ladder is still structural (level 2 says the fields are there, not that the award is sound), and a seller-signed quote is not required. |
| W-22 | Medium | **The tests did not pin the claims.** With the signer-org check, revocation and the quote-hash requirement deleted, every Rust test passed; four archive guards could be deleted with everything green; some reject vectors failed for an unrelated reason; the fuzzer could not generate any class in this section. | **Fixed** progressively ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)–[#31](https://github.com/rivletio/secure-job-envelope/pull/31)): every reject vector's reason is pinned per implementation; one test per archive guard; verification cases carry the refusal reason; 33 + 18 single-rule mutations each fail a test. Fuzzer extension and canonical-number vectors: **in progress**. |
| W-23 | Medium | **The published JSON Schema was stale**: it rejected every signed or hash-bound award, and a schema-driven sanitizer would strip the signature. | **In progress**. |

## C. Lifecycle and business logic

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-24 | Medium | **An award commits to quote content the buyer was never shown** (exception price deltas, freight, assumptions, expiry). Form parsing: "1,250.00" silently dropped the price line, "0.004" stored 0, a target quantity of "5,000" stored 1. | Duplicate price lines **fixed** ([#27](https://github.com/rivletio/secure-job-envelope/pull/27)). Display and input parsing: **in progress**. |
| W-25 | Medium | A seller could not re-quote after an amendment (the one-quote rule counted stale quotes); a 65th quote was accepted and the traveler then silently vanished on reload. | **In progress**. **Limit:** a quote's `seller.org_id` is self-asserted unless signed, so a party able to add quotes to a buyer's copy can still crowd it (64 quotes shared by all sellers). |
| W-26 | Low | Two definitions of "locked": an award naming no bound quote was level 1 yet locked. | **In progress**. **Limit:** MCP's lock is derived from the document it is handed — delete `award` and an amendment succeeds; the party holding the authoritative copy is responsible for it. |
| W-27 | Low | The award dialog pre-filled ship-to and ops from an imported file; the desk could not delete a traveler. | **In progress**. |
| W-28 | Low | Two tabs: the last writer replaced the whole store, so a stale tab reverted a locked traveler. | **Fixed** ([#32](https://github.com/rivletio/secure-job-envelope/pull/32)). |
| W-29 | Info | The "append-only" audit log is a ring of the last 100 events in the same editable browser storage as the travelers; refusals are not logged. | **Limit.** It is a convenience, not an audit trail. |

## D. Confidentiality and key lifecycle

| ID | Severity | Weakness | Status |
|---|---|---|---|
| W-30 | High | **No bid confidentiality between sellers.** The whole traveler was the unit of exchange: a re-sent RFQ handed seller B seller A's price, the winner's file carried every losing bid, and a loser learned who won and where it ships. | Rule **written and tested** ([#32](https://github.com/rivletio/secure-job-envelope/pull/32), `projection.ts`). Applied automatically when sealing: **in progress**. |
| W-31 | Medium | **Forward-secret mode silently lost messages.** A sender picked a one-time key at random with no memory: one honest sender sealing 20 travelers to an 8-key bundle left most permanently unopenable, each reported "forward-secret". | Sender-side tracking: **in progress**. **Limit:** two *different* senders can still collide, and anyone can spend a published pool; only a coordinating service could prevent that, and the format has none. |
| W-32 | Medium | **Deletion of a used one-time key was weaker than documented.** The docs said "deleted before the secret is used"; the code decrypted first. The key was spent before the import decision, so a refusal lost the envelope; a failed write was silent; two tabs or two server processes resurrected spent keys. | Two-phase open **fixed** ([#31](https://github.com/rivletio/secure-job-envelope/pull/31), [#32](https://github.com/rivletio/secure-job-envelope/pull/32)): spent only once the traveler is admitted; a failed deletion is reported; documents corrected. Read-back after write, multi-tab and multi-process handling: **in progress**. |
| W-33 | Low | Keystore key-derivation parameters were read from the file without bounds (unlock could be made to hang); the org id in the header was not authenticated. | **In progress**. |
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
| W-41 | Low | No Content-Security-Policy; a third-party stylesheet loaded on the page where the passphrase is typed. | **In progress**. |
| W-42 | Low | The demo site's service worker controlled the desk's path: a desk fix would reach returning visitors one visit late. | **In progress**. |
| W-43 | Info | An unused `innerHTML` path in the demo site's DOM helper. | **In progress**. |

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
| W-50 | High | **The trust root is all-powerful and unaccountable.** No versioning, transparency or key continuity. It can add a second entry for any org and sign as it, or a newer encryption key and read what is sealed to it. `GOVERNANCE.md` said the root "cannot by itself produce a valid buyer award signature" — false. | **Limit**; document corrected. Refusing an older directory and confirming a root change on the desk: **in progress** (W-07). |
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

---

## How the fixes were checked

- **Shared vectors, both implementations.** Reject vectors carry the reason each
  implementation must give (`conformance/travelers/reject-reasons.json`); envelope cases
  carry the stage that must refuse (`envelope-cases.json`); verification cases carry the
  refusal reason (`verify-cases.json`, `directory-cases.json`). The generator states each
  case's required outcome and fails if the TypeScript implementation disagrees; the Rust
  runner then checks the same files independently.
- **Mutation.** For each security rule, the rule was deleted and a test had to fail: 8
  mutations for the envelope shape, 33 for verification, 18 for the receive policy. One
  survivor was found this way and closed.
- **Bytes, not objects.** Travelers, envelopes and directories are parsed from the bytes
  as received wherever they cross a company boundary; the vectors are replayed from bytes.
- **A browser.** The desk's receive path was driven in Chromium: forged award, rollback,
  body swap, buyer change, two tabs.
- **Not checked by anything here:** the cryptographic libraries themselves, side channels,
  the browser, the host the desk is served from, or any party's operational handling of
  keys.
