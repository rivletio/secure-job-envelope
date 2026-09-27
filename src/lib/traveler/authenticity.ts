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
  const entry = entryByKid(dir, s.kid, at);
  if (!entry) return { kid: s.kid, ok: false, reason: "no active directory entry for kid" };
  if (claimedOrg && entry.org_id !== claimedOrg) {
    return { kid: s.kid, ok: false, org_id: entry.org_id, reason: "signer org does not match author org" };
  }
  const ok = verifyBody(domain, body, s.sig, hexToBytes(entry.public_key));
  return { kid: s.kid, ok, org_id: entry.org_id, reason: ok ? undefined : "signature does not verify" };
}

/** Per-signature results for a traveler's buyer authorship signatures. */
export function verifyTravelerSignatures(
  t: Traveler,
  dir: Directory,
  rootPublicKeyHex: string,
  at?: Date,
): SigCheck[] {
  if (!verifyDirectory(dir, rootPublicKeyHex)) {
    return [{ kid: dir.root_kid, ok: false, reason: "directory does not verify against the trust root" }];
  }
  const body = travelerSignatureBody(t);
  return (t.signatures ?? []).map((s) => checkSig(SIG_DOMAIN.traveler, body, s, t.buyer.org_id, dir, at));
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
  if (!verifyDirectory(dir, rootPublicKeyHex)) {
    return { kid: dir.root_kid, ok: false, reason: "directory does not verify against the trust root" };
  }
  return checkSig(SIG_DOMAIN.quote, quoteSignatureBody(q), q.sig, q.seller.org_id, dir, at);
}

/** ITAR gate elevated to directory attestation (caveat 3): an ITAR traveler's
 *  seller must hold the ITAR capability in the directory, not merely self-declare
 *  `seller.itar`. Returns null if allowed, or a reason string if refused. */
export function itarAttestationBlocker(
  t: Traveler,
  q: Quote,
  dir: Directory,
  at?: Date,
): string | null {
  if (!t.itar) return null;
  if (!q.seller.org_id) return "ITAR traveler: seller has no org_id to attest against the directory";
  if (!orgHasCapability(dir, q.seller.org_id, "itar", at)) {
    return "ITAR traveler: seller is not attested for ITAR in the directory";
  }
  return null;
}
