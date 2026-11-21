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
import { quoteableBody, travelerHash } from "./hash.ts";
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
  if (s.alg !== SIG_ALG) return { kid: s.kid, ok: false, reason: "unsupported alg" };
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

/** Per-signature results for a traveler's buyer authorship signatures. */
export function verifyTravelerSignatures(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck[] {
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return [{ kid: dir.root_kid, ok: false, reason: "directory does not verify against the trust root" }];
  }
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

export function verifyQuoteSignature(
  q: Quote,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck | undefined {
  if (!q.sig) return undefined;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return { kid: dir.root_kid, ok: false, reason: "directory does not verify against the trust root" };
  }
  // Fail closed if the quote body cannot be canonicalized. A quote's opaque
  // assumptions / capacity blobs allow arbitrary values, so a hostile number
  // (1e308, below 1e-5, > 2^53) would otherwise throw out of canonicalJson here.
  let body: string;
  try {
    body = quoteSignatureBody(q);
  } catch {
    return { kid: q.sig.kid, ok: false, reason: "quote body is not canonicalizable" };
  }
  return checkSig(SIG_DOMAIN.quote, body, q.sig, q.seller.org_id, dir, when);
}

/** Verify the buyer's signature over the award + ship-to. Returns:
 *  - `undefined` if the traveler carries no award (nothing to check);
 *  - a failing check if an award is present but unsigned, or signed by an org
 *    other than the buyer, or over a changed award / ship-to / revision;
 *  - a passing check only when the buyer (as named by the traveler and bound
 *    through the directory) signed exactly this award and ship-to.
 *  An award present without a valid buyer signature is an authenticity failure,
 *  not a silent accept — this is the guard against a forged award or a redirected
 *  ship-to sealed to the winner by a non-buyer. */
export function verifyAwardSignature(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck | undefined {
  if (!t.award) return undefined;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return { kid: dir.root_kid, ok: false, reason: "directory does not verify against the trust root" };
  }
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
  return checkSig(SIG_DOMAIN.award, body, t.award.sig, t.buyer.org_id, dir, when);
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
 *  against the trust root. Returns null if allowed, or a reason string if
 *  refused. The root check matches its sibling verifiers, so a self-made or
 *  tampered directory cannot grant the capability. */
export function itarAttestationBlocker(
  t: Traveler,
  q: Quote,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): string | null {
  if (!t.itar) return null;
  const when = at ?? new Date();
  if (!verifyDirectory(dir, rootPublicKeyHex, when)) {
    return "ITAR traveler: key directory does not verify against the trust root";
  }
  if (!q.seller.org_id) return "ITAR traveler: seller has no org_id to attest against the directory";
  if (!orgHasCapability(dir, q.seller.org_id, "itar", when)) {
    return "ITAR traveler: seller is not attested for ITAR in the directory";
  }
  return null;
}
