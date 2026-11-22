/** Binds post-quantum signatures to travelers and quotes and verifies them
 *  against the signed key directory. This is where authenticity stops being a
 *  claim and becomes enforced: a traveler's buyer signature must resolve, through
 *  the directory, to the org named in the body (caveat 1/2), and an ITAR
 *  traveler's seller must hold the directory-attested ITAR capability (caveat 3).
 *
 *  Signing lives here for the CLI / server / test-vector path. The browser desk
 *  only ever *verifies* — it must not hold ML-DSA private keys (see SECURITY).
 */
import { canonicalJson } from "./canonical.ts";
import { parseQuote, parseTraveler } from "./conformance.ts";
import { quoteableBody, travelerHash, sha384Hex } from "./hash.ts";
import { SIG_ALG, SIG_DOMAIN, signBody, verifyBody } from "./signature.ts";
import { hexToBytes } from "./bytes.ts";
import { entryByKid, orgHasCapability, verifyDirectory, type Directory } from "./directory.ts";
import type { Traveler, Quote, Signature } from "./types.ts";

/** Exact bytes a buyer signs: the canonical quoteable body (== traveler_hash preimage). */
export function travelerSignatureBody(t: Traveler): string {
  return canonicalJson(quoteableBody(t));
}

/** Exact bytes a seller signs: the canonical quote with its own signature removed. */
export function quoteSignatureBody(q: Quote): string {
  const { sig: _omit, ...rest } = q;
  void _omit;
  return canonicalJson(rest);
}

/** The awarded quote's content hash: `sha384:` + hex of the exact bytes the seller signs
 *  (the quote minus its own signature). This is what the buyer's award signature commits to
 *  via `award.quote_hash`, so the award binds the quote's priced content (unit price, currency,
 *  lead time, …), not merely its `quote_id`. Mirrors the Rust hash in `verify_award_signature`. */
export function quoteContentHash(q: Quote): string {
  return sha384Hex(quoteSignatureBody(q));
}

export function signTraveler(t: Traveler, kid: string, secretKey: Uint8Array): Signature {
  return { alg: SIG_ALG, kid, sig: signBody(SIG_DOMAIN.traveler, travelerSignatureBody(t), secretKey) };
}

export function signQuote(q: Quote, kid: string, secretKey: Uint8Array): Signature {
  return { alg: SIG_ALG, kid, sig: signBody(SIG_DOMAIN.quote, quoteSignatureBody(q), secretKey) };
}

/** Exact bytes the buyer signs to authorize an award: the award decision and the
 *  ship-to, bound to the exact traveler revision via `traveler_hash` (and excluding
 *  the award's own signature). A party who is not the buyer — e.g. a losing bidder
 *  who can seal an envelope to the winner — cannot produce this, so a forged award
 *  or an altered ship-to no longer verifies. Throws if there is no award. */
export function awardSignatureBody(t: Traveler): string {
  if (!t.award) throw new Error("no award to sign");
  const { sig: _omit, ...award } = t.award;
  void _omit;
  return canonicalJson({
    spec: t.spec,
    traveler_id: t.traveler_id,
    traveler_hash: travelerHash(t),
    award,
    ship_to: t.ship_to ?? null,
  });
}

export function signAward(t: Traveler, kid: string, secretKey: Uint8Array): Signature {
  return { alg: SIG_ALG, kid, sig: signBody(SIG_DOMAIN.award, awardSignatureBody(t), secretKey) };
}

export type SigCheck = { kid: string; ok: boolean; org_id?: string; reason?: string };

function checkSig(
  domain: string,
  body: string,
  s: Signature,
  claimedOrg: string | undefined,
  dir: Directory,
  at?: Date,
): SigCheck {
  // (No algorithm check here: every caller validates the document first, and a valid
  // signature object can only declare SIG_ALG.)
  // Authorship must name an org and bind the signature to it. A missing org_id is
  // a hard failure — not an implicit "any directory member will do" — matching the
  // Rust verifier and closing the unbound-author acceptance gap.
  if (!claimedOrg) {
    return { kid: s.kid, ok: false, reason: "author names no org_id to bind the signature to" };
  }
  const entry = entryByKid(dir, s.kid, at);
  if (!entry) return { kid: s.kid, ok: false, reason: "no active in-window directory entry for kid" };
  if (entry.org_id !== claimedOrg) {
    return { kid: s.kid, ok: false, org_id: entry.org_id, reason: "signer org does not match author org" };
  }
  let ok = false;
  try {
    ok = verifyBody(domain, body, s.sig, hexToBytes(entry.public_key));
  } catch {
    ok = false; // malformed key material fails closed, never throws
  }
  return { kid: s.kid, ok, org_id: entry.org_id, reason: ok ? undefined : "signature does not verify" };
}

function isValid(parse: () => unknown): boolean {
  try {
    parse();
    return true;
  } catch {
    return false;
  }
}

/** The stock "directory failed to verify against the trust root" result, shared by the
 *  three verify* functions so the reason string lives in exactly one place. */
function dirUnverified(): SigCheck {
  // No kid: the only id on hand is one an unverified directory declares for itself.
  return { kid: "", ok: false, reason: "directory does not verify against the trust root" };
}

/* The verifiers below come in two layers.
 *
 * The exported ones take a directory and a root and ESTABLISH them first: the directory
 * verifies against the root at the instant asked about. The unexported `…Checks` take
 * that as given. Verifying a directory means canonicalizing and hashing all of it, so a
 * caller with many signatures to check must do it once, not once per signature: a
 * traveler with 64 junk quote "signatures" used to cost 66 verifications of a directory
 * the sender chose the size of. `verificationReport` and `itarAttestationBlockers`
 * establish once and then call the inner layer. Nothing outside this file can reach the
 * inner layer, so there is no way to hand it a directory that was not just verified. */

/** Buyer authorship checks. `dir` is established and `t` is a valid traveler. */
function travelerChecks(t: Traveler, dir: Directory, when: Date): SigCheck[] {
  // Fail closed if the body cannot be canonicalized (a non-canonical number in an
  // opaque field, say): a body that cannot be produced cannot have been signed, so
  // every signature over it is unverifiable — never an uncaught throw on hostile input.
  let body: string;
  try {
    body = travelerSignatureBody(t);
  } catch {
    return (t.signatures ?? []).map((s) => ({
      kid: s.kid,
      ok: false,
      reason: "traveler body is not canonicalizable",
    }));
  }
  return (t.signatures ?? []).map((s) => checkSig(SIG_DOMAIN.traveler, body, s, t.buyer.org_id, dir, when));
}

const NOT_A_TRAVELER: SigCheck = { kid: "", ok: false, reason: "not a valid traveler" };

/** Per-signature results for a traveler's buyer authorship signatures. */
export function verifyTravelerSignatures(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck[] {
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return [dirUnverified()];
  }
  if (!isValid(() => parseTraveler(t))) {
    return [{ ...NOT_A_TRAVELER }];
  }
  return travelerChecks(t, dir, when);
}

/** True iff at least one valid buyer signature is present (authorship established). */
export function travelerIsAuthentic(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): boolean {
  const checks = verifyTravelerSignatures(t, dir, rootPublicKeyHex, at);
  return checks.some((c) => c.ok);
}

/** A quote's seller signature; `undefined` if it carries none. `dir` is established. */
function quoteCheck(q: Quote, dir: Directory, when: Date): SigCheck | undefined {
  if (!q.sig) return undefined;
  // A signature over something that is not a valid quote establishes nothing (the
  // Rust verifier parses before it verifies; a typed argument here is only a claim).
  if (!isValid(() => parseQuote(q))) {
    return { kid: q.sig.kid, ok: false, reason: "not a valid quote" };
  }
  // Fail closed if the quote body cannot be canonicalized.
  let body: string;
  try {
    body = quoteSignatureBody(q);
  } catch {
    return { kid: q.sig.kid, ok: false, reason: "quote body is not canonicalizable" };
  }
  return checkSig(SIG_DOMAIN.quote, body, q.sig, q.seller.org_id, dir, when);
}

export function verifyQuoteSignature(
  q: Quote,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck | undefined {
  if (!q.sig) return undefined;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return dirUnverified();
  }
  return quoteCheck(q, dir, when);
}

/** Verify the buyer's signature over the award + ship-to, and that it commits to the
 *  awarded quote's priced content. Returns:
 *  - `undefined` if the traveler carries no award (nothing to check);
 *  - a failing check if an award is present but unsigned, or signed by an org
 *    other than the buyer, or over a changed award / ship-to / revision, or whose
 *    `quote_hash` does not bind the awarded quote actually present on the traveler;
 *  - a passing check only when the buyer (as named by the traveler and bound
 *    through the directory) signed exactly this award and ship-to, AND the awarded
 *    quote is present and still hashes to the buyer-signed `quote_hash`.
 *  An award present without a valid buyer signature is an authenticity failure,
 *  not a silent accept — this is the guard against a forged award or a redirected
 *  ship-to sealed to the winner by a non-buyer. The `quote_hash` binding closes the
 *  completeness gap: the award commits to the exact priced quote (unit price, currency,
 *  lead time), so a swapped price on the awarded quote — even an unsigned one — is refused.
 *  A stripped awarded quote is a hard failure (its priced content cannot be re-verified). */
export function verifyAwardSignature(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck | undefined {
  if (!t.award) return undefined;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return dirUnverified();
  }
  if (!isValid(() => parseTraveler(t))) {
    return { ...NOT_A_TRAVELER };
  }
  return awardCheck(t, dir, when);
}

/** The buyer's award; `undefined` if the traveler carries none. `dir` is established
 *  and `t` is a valid traveler. */
function awardCheck(t: Traveler, dir: Directory, when: Date): SigCheck | undefined {
  if (!t.award) return undefined;
  if (!t.award.sig) {
    return { kid: "", ok: false, reason: "award is present but not signed by the buyer" };
  }
  // Fail closed if the award body cannot be canonicalized (a hostile number in an
  // opaque field would otherwise throw out of canonicalJson here).
  let body: string;
  try {
    body = awardSignatureBody(t);
  } catch {
    return { kid: t.award.sig.kid, ok: false, reason: "award body is not canonicalizable" };
  }
  const sigCheck = checkSig(SIG_DOMAIN.award, body, t.award.sig, t.buyer.org_id, dir, when);
  if (!sigCheck.ok) return sigCheck;
  // The buyer's signature is valid over the award body, which includes `award.quote_hash`
  // (it rides inside `award`). Now enforce that it actually binds the priced quote: a signed
  // award MUST carry a quote_hash, the awarded quote MUST be present, and it MUST still hash
  // to the signed value. Without this, an absent or unsigned awarded quote could have its
  // price swapped while the award signature still verified.
  const quoteHash = t.award.quote_hash;
  if (!quoteHash) {
    return { ...sigCheck, ok: false, reason: "signed award does not bind a quote_hash" };
  }
  const quoteId = t.award.quote_id;
  const awarded = (t.quotes ?? []).find((q) => q.quote_id === quoteId);
  if (!awarded) {
    return {
      ...sigCheck,
      ok: false,
      reason: "awarded quote is not present to verify its priced content",
    };
  }
  let computed: string;
  try {
    computed = quoteContentHash(awarded);
  } catch {
    return { ...sigCheck, ok: false, reason: "awarded quote body is not canonicalizable" };
  }
  if (computed !== quoteHash) {
    return {
      ...sigCheck,
      ok: false,
      reason: "awarded quote content does not match the buyer-signed quote_hash",
    };
  }
  // The award is the buyer's and commits to this quote's content. It must also commit
  // to something determinate: a quote made against THIS revision of the part (a quote
  // for an earlier revision prices a different part), carrying a price for the quantity
  // awarded. Both are facts of the signed bytes, so both implementations decide them
  // identically.
  if (awarded.traveler_hash_quoted !== travelerHash(t)) {
    return { ...sigCheck, ok: false, reason: "awarded quote is not bound to this revision" };
  }
  const awardedQty = t.award.qty;
  if (!awarded.pricing.lines.some((l) => l.qty === awardedQty)) {
    return { ...sigCheck, ok: false, reason: "awarded quote has no price for the awarded quantity" };
  }
  return sigCheck;
}

/** True iff the traveler has an award and it carries a valid buyer signature. */
export function awardIsAuthentic(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): boolean {
  return verifyAwardSignature(t, dir, rootPublicKeyHex, at)?.ok === true;
}

/** ITAR gate elevated to directory attestation (caveat 3): an ITAR traveler's
 *  seller must hold the ITAR capability in a directory that itself verifies
 *  against the trust root — and the quote must be SIGNED by that seller. Returns
 *  null if allowed, or a reason string if refused.
 *
 *  The signature is what makes the attestation mean anything: `seller.org_id` is a
 *  field the quote's author types. Without a verified signature binding the quote to
 *  that org's directory key, an unsigned quote that merely names an attested org — or
 *  one signed by some other org — passed this gate. The root check matches its sibling
 *  verifiers, so a self-made or tampered directory cannot grant the capability. */
export function itarAttestationBlocker(
  t: Traveler,
  q: Quote,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): string | null {
  // Fail closed on a document that is not a traveler at all — never read it as
  // "not ITAR" (the order and the reasons below are the Rust gate's, exactly).
  if (!isValid(() => parseTraveler(t))) return "ITAR gate: not a valid traveler";
  if (!t.itar) return null;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return "ITAR traveler: key directory does not verify against the trust root";
  }
  return itarBlockerFor(q, dir, when);
}

/** The gate's answer for one quote on an ITAR traveler. `dir` is established. */
function itarBlockerFor(q: Quote, dir: Directory, when: Date): string | null {
  if (!isValid(() => parseQuote(q))) return "ITAR gate: not a valid quote";
  if (!q.seller.org_id) return "ITAR traveler: seller has no org_id to attest against the directory";
  if (quoteCheck(q, dir, when)?.ok !== true) {
    return "ITAR traveler: quote is not signed by the seller it names";
  }
  if (!orgHasCapability(dir, q.seller.org_id, "itar", when)) {
    return "ITAR traveler: seller is not attested for ITAR in the directory";
  }
  return null;
}

/** `itarAttestationBlocker` for every quote the traveler carries, in document order —
 *  the same answers, with the directory verified once rather than once per quote. */
export function itarAttestationBlockers(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): { quote_id: string; blocker: string | null }[] {
  if (!isValid(() => parseTraveler(t))) return [];
  const quotes = t.quotes ?? [];
  if (!t.itar) return quotes.map((q) => ({ quote_id: q.quote_id, blocker: null }));
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    const blocker = "ITAR traveler: key directory does not verify against the trust root";
    return quotes.map((q) => ({ quote_id: q.quote_id, blocker }));
  }
  return quotes.map((q) => ({ quote_id: q.quote_id, blocker: itarBlockerFor(q, dir, when) }));
}

/** What verification established about a traveler: one function, one answer, for every
 *  caller that has to decide whether to trust a received document (the desk's panel and
 *  import gate, the MCP server, a script). Mirrors the Rust core's `verify_report`
 *  field for field and reason for reason. */
export type VerificationReport = {
  /** One check per buyer signature (empty: unsigned). If the directory does not verify,
   *  or the document is not a valid traveler, a single refused check says so. */
  authorship: SigCheck[];
  /** The buyer's award signature; `undefined` iff the traveler carries no award. */
  award: SigCheck | undefined;
  /** Per quote, in document order; `check` is `undefined` for an unsigned quote. */
  quotes: { quote_id: string; check: SigCheck | undefined }[];
  /** At least one valid buyer signature. */
  authored: boolean;
  /** The traveler is the buyer's and, if it carries an award, so is the award. */
  verified: boolean;
};

export function verificationReport(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): VerificationReport {
  const when = at ?? new Date();
  // Established once, for every check that follows: the directory against the root, and
  // the document as a traveler. If either fails, a single refused check says which, the
  // award (if there is one) carries the same refusal, and no quote is reported.
  const refusal = !verifyDirectory(dir, rootPublicKeyHex, when)
    ? dirUnverified()
    : !isValid(() => parseTraveler(t))
      ? { ...NOT_A_TRAVELER }
      : null;
  if (refusal) {
    return {
      authorship: [refusal],
      award: t.award ? { ...refusal } : undefined,
      quotes: [],
      authored: false,
      verified: false,
    };
  }
  const authorship = travelerChecks(t, dir, when);
  const award = awardCheck(t, dir, when);
  const quotes = (t.quotes ?? []).map((q) => ({ quote_id: q.quote_id, check: quoteCheck(q, dir, when) }));
  const authored = authorship.some((c) => c.ok);
  return { authorship, award, quotes, authored, verified: authored && (award === undefined || award.ok) };
}
