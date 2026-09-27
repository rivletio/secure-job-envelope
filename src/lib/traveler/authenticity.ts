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
import { quoteableBody } from "./hash.ts";
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
  const body = travelerSignatureBody(t);
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
  return checkSig(SIG_DOMAIN.quote, quoteSignatureBody(q), q.sig, q.seller.org_id, dir, when);
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
