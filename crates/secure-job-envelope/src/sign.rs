//! Post-quantum authorship signatures — CNSA 2.0 profile (ML-DSA-87, FIPS 204).
//!
//! Mirrors `src/lib/traveler/signature.ts` byte-for-byte: the signed message is
//! `domain ‖ 0x00 ‖ canonical_body`, signed with the deterministic ML-DSA
//! variant (rnd = 0), so a signature produced by the TypeScript reference
//! verifies here and vice versa. The shared `conformance/signatures/*` vectors
//! pin this agreement across the two independent codebases.

use crate::canonical_json;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, SigningKey, VerifyingKey, B32,
};
use serde_json::Value;
use sha2::{Digest, Sha384};

pub const SIG_ALG: &str = "ML-DSA-87";
pub const DOMAIN_TRAVELER: &str = "sje-sig/traveler/0.1.0";
pub const DOMAIN_QUOTE: &str = "sje-sig/quote/0.1.0";
pub const DOMAIN_AWARD: &str = "sje-sig/award/0.1.0";
pub const DOMAIN_DIRECTORY: &str = "sje-sig/directory/0.1.0";
pub const DOMAIN_PREKEYS: &str = "sje-sig/prekeys/0.1.0";

/// Bytes actually signed: the domain tag, a NUL, then the canonical body.
fn signed_message(domain: &str, canonical_body: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 1 + canonical_body.len());
    m.extend_from_slice(domain.as_bytes());
    m.push(0);
    m.extend_from_slice(canonical_body.as_bytes());
    m
}

/// Deterministic keypair from a 32-byte seed. Returns (public_key_hex, signing_key).
pub fn keypair_from_seed(seed: &[u8; 32]) -> (String, SigningKey<MlDsa87>) {
    let sk = SigningKey::<MlDsa87>::from_seed(&B32::from(*seed));
    let pk_hex = hex::encode(sk.verifying_key().encode().as_slice());
    (pk_hex, sk)
}

/// Deterministic ML-DSA-87 signature (lowercase hex) over the domain-separated body.
pub fn sign_body(domain: &str, canonical_body: &str, sk: &SigningKey<MlDsa87>) -> String {
    let sig: Signature<MlDsa87> = sk.sign(&signed_message(domain, canonical_body));
    hex::encode(sig.encode().as_slice())
}

/// Verify a hex ML-DSA-87 signature over the domain-separated body against a hex public key.
/// Any malformed input (bad hex, wrong length, bad signature) verifies as false.
pub fn verify_body(domain: &str, canonical_body: &str, sig_hex: &str, pk_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(pk_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(pk_arr) = EncodedVerifyingKey::<MlDsa87>::try_from(&pk_bytes[..]) else {
        return false;
    };
    let Ok(sig_arr) = EncodedSignature::<MlDsa87>::try_from(&sig_bytes[..]) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&pk_arr);
    let Some(sig) = Signature::<MlDsa87>::decode(&sig_arr) else {
        return false;
    };
    vk.verify(&signed_message(domain, canonical_body), &sig).is_ok()
}

pub const DIRECTORY_SPEC: &str = "sje-directory/0.1.0";
pub const PREKEY_BUNDLE_SPEC: &str = "sje-prekeys/0.1.0";

/// Verify a signed key directory (JSON) against the trust-root public key (hex),
/// and that `at_ms` falls within the directory's own freshness window
/// `[issued_at, valid_until)`. The window is part of the signed body, so it
/// cannot be widened without breaking the root signature; enforcing it here
/// additionally bounds how long a stale (but validly-signed) directory can be
/// replayed — the in-band limit on revocation rollback. False on any malformed
/// or out-of-window input. The signed body is the directory with its own `sig`
/// removed, then canonicalized — identical bytes to the TypeScript `directoryBody`.
pub fn verify_directory(dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    let Ok(mut v) = serde_json::from_str::<Value>(dir_json) else {
        return false;
    };
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    if obj.get("spec").and_then(Value::as_str) != Some(DIRECTORY_SPEC) {
        return false;
    }
    let issued = obj
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(crate::rfc3339_millis);
    let until = obj
        .get("valid_until")
        .and_then(Value::as_str)
        .and_then(crate::rfc3339_millis);
    let (Some(issued), Some(until)) = (issued, until) else {
        return false;
    };
    if !(issued <= at_ms && at_ms < until) {
        return false;
    }
    let Some(sig) = obj.remove("sig").and_then(|s| s.as_str().map(str::to_string)) else {
        return false;
    };
    let Ok(canonical) = canonical_json(&v) else {
        return false;
    };
    verify_body(DOMAIN_DIRECTORY, &canonical, &sig, root_pk_hex)
}

/// Single source of truth for "is this entry usable at `at_ms`": active status,
/// the expected algorithm, and inside `[valid_from, valid_until)`. Shared by the
/// kid and org lookups so they can never diverge on what counts as valid (the
/// TypeScript side shares one `inWindow` the same way). Malformed entries → false.
fn entry_active_in_window(e: &Value, at_ms: i64) -> bool {
    (|| -> Option<bool> {
        if e.get("status").and_then(Value::as_str)? != "active" {
            return None;
        }
        if e.get("alg").and_then(Value::as_str)? != SIG_ALG {
            return None;
        }
        let from = crate::rfc3339_millis(e.get("valid_from")?.as_str()?)?;
        let until = crate::rfc3339_millis(e.get("valid_until")?.as_str()?)?;
        Some(from <= at_ms && at_ms < until)
    })()
    .unwrap_or(false)
}

/// Look up a directory entry by kid that is active, of the expected algorithm,
/// and in its validity window at `at_ms`, returning (org_id, public_key_hex).
/// Mirrors the TypeScript `entryByKid` / `inWindow`, so an expired, not-yet-valid,
/// revoked, or wrong-algorithm entry never authenticates. Malformed entries are
/// skipped rather than aborting the search.
pub fn directory_entry_by_kid(dir_json: &str, kid: &str, at_ms: i64) -> Option<(String, String)> {
    let v: Value = serde_json::from_str(dir_json).ok()?;
    v.get("entries")?.as_array()?.iter().find_map(|e| {
        if e.get("kid").and_then(Value::as_str) != Some(kid) || !entry_active_in_window(e, at_ms) {
            return None;
        }
        Some((
            e.get("org_id")?.as_str()?.to_string(),
            e.get("public_key")?.as_str()?.to_string(),
        ))
    })
}

/// Verify a traveler's buyer-authorship signature against a signed directory at
/// `at_ms`. True iff the directory verifies (and is in-window) against
/// `root_pk_hex`, the buyer names an org_id, and at least one of the traveler's
/// signatures resolves to an active, in-window directory entry whose org matches
/// `buyer.org_id` and whose ML-DSA-87 key verifies the canonical quoteable body.
pub fn verify_traveler_authorship(
    traveler_json: &str,
    dir_json: &str,
    root_pk_hex: &str,
    at_ms: i64,
) -> bool {
    if !verify_directory(dir_json, root_pk_hex, at_ms) {
        return false;
    }
    let Ok(t) = crate::parse_traveler(traveler_json) else {
        return false;
    };
    let Some(buyer_org) = t.buyer.org_id.clone() else {
        return false;
    };
    let Ok(body_value) = serde_json::to_value(crate::quoteable_from(&t)) else {
        return false;
    };
    let Ok(canonical) = canonical_json(&body_value) else {
        return false;
    };
    for s in t.signatures.as_deref().unwrap_or(&[]) {
        if s.alg != SIG_ALG {
            continue;
        }
        if let Some((org, pk)) = directory_entry_by_kid(dir_json, &s.kid, at_ms) {
            if org == buyer_org && verify_body(DOMAIN_TRAVELER, &canonical, &s.sig, &pk) {
                return true;
            }
        }
    }
    false
}

/// Verify the buyer's signature over an award + ship-to against the signed
/// directory at `at_ms`. True iff the directory verifies (in-window) against
/// `root_pk_hex`, the traveler carries an award with an ML-DSA-87 signature, the
/// buyer names an org_id, and that signature resolves to an active, in-window
/// directory entry whose org matches `buyer.org_id` and whose key verifies the
/// canonical award body `{spec, traveler_id, traveler_hash, award (minus sig),
/// ship_to}`. A party who is not the buyer — e.g. a losing bidder who can seal an
/// envelope to the winner — cannot produce this, so a forged award or altered
/// ship-to is refused. The award body includes `award.quote_hash`, and this verifier
/// additionally requires that binding to hold: the awarded quote MUST be present in
/// `quotes` and still hash to the signed `quote_hash`, so an absent or unsigned awarded
/// quote cannot have its priced content swapped under a still-valid award signature (a
/// stripped awarded quote is a hard failure). Mirrors the TypeScript `verifyAwardSignature`;
/// false on a missing or unsigned award, a non-buyer signer, an absent/mismatched awarded
/// quote, or any malformed input.
pub fn verify_award_signature(
    traveler_json: &str,
    dir_json: &str,
    root_pk_hex: &str,
    at_ms: i64,
) -> bool {
    if !verify_directory(dir_json, root_pk_hex, at_ms) {
        return false;
    }
    // Parse: validates the document and yields the traveler_hash that binds the award.
    let Ok(t) = crate::parse_traveler(traveler_json) else {
        return false;
    };
    let Some(award) = t.award.as_ref() else {
        return false;
    };
    let Some(sig) = award.sig.as_ref() else {
        return false;
    };
    if sig.alg != SIG_ALG {
        return false;
    }
    let Some(buyer_org) = t.buyer.org_id.clone() else {
        return false;
    };
    let Ok(traveler_hash) = crate::traveler_hash(&t) else {
        return false;
    };
    // Build the signed body from the raw JSON (award minus its own sig, plus
    // ship_to), so the canonical bytes match the TypeScript awardSignatureBody.
    //
    // Parity invariant: this reuses the RAW json for `award`/`ship_to` while TS
    // signs over the PARSED traveler. That is only sound because parse_traveler
    // (called above) already enforced the strict schema — no unknown keys, and no
    // normalizing transform on these fields — so the raw and parsed values carry
    // the same keys and the same scalar content, and canonical_json erases the one
    // legal difference (integer-valued float vs integer rendering) identically on
    // both sides. If any award/ship_to field ever gains a serde/zod transform or a
    // default, this must switch to serializing the parsed struct instead.
    let Ok(v) = serde_json::from_str::<Value>(traveler_json) else {
        return false;
    };
    let mut award_value = v.get("award").cloned().unwrap_or(Value::Null);
    if let Some(obj) = award_value.as_object_mut() {
        obj.remove("sig");
    }
    let ship_to = v.get("ship_to").cloned().unwrap_or(Value::Null);
    let body = serde_json::json!({
        "spec": v.get("spec").cloned().unwrap_or(Value::Null),
        "traveler_id": v.get("traveler_id").cloned().unwrap_or(Value::Null),
        "traveler_hash": traveler_hash,
        "award": award_value,
        "ship_to": ship_to,
    });
    let Ok(canonical) = canonical_json(&body) else {
        return false;
    };
    let Some((org, pk)) = directory_entry_by_kid(dir_json, &sig.kid, at_ms) else {
        return false;
    };
    if !(org == buyer_org && verify_body(DOMAIN_AWARD, &canonical, &sig.sig, &pk)) {
        return false;
    }
    // Quote-content binding: the signed award body includes `quote_hash` (it rides inside
    // `award`), so the buyer committed to the exact priced quote. Now require that binding to
    // hold: a signed award MUST carry a quote_hash, the awarded quote MUST be present in
    // `quotes`, and it MUST still hash to the signed value — otherwise an absent or unsigned
    // awarded quote could have its price swapped under a still-valid award signature. The quote
    // content hash is `sha384:` + hex of canonical(quote minus its own `sig`) — the same bytes
    // the seller signs, built from the RAW json under the same parity invariant as the award body
    // above (and as `verify_quote_signature`), so it matches the TypeScript `quoteContentHash`.
    let Some(quote_hash) = award.quote_hash.as_deref() else {
        return false;
    };
    let Some(quotes) = v.get("quotes").and_then(Value::as_array) else {
        return false;
    };
    let Some(awarded) = quotes
        .iter()
        .find(|q| q.get("quote_id").and_then(Value::as_str) == Some(award.quote_id.as_str()))
    else {
        return false;
    };
    let mut awarded_body = awarded.clone();
    if let Some(obj) = awarded_body.as_object_mut() {
        obj.remove("sig");
    }
    let Ok(canon_quote) = canonical_json(&awarded_body) else {
        return false;
    };
    let computed = format!("sha384:{}", hex::encode(Sha384::digest(canon_quote.as_bytes())));
    computed == quote_hash
}

/// Whether an org is attested — by an active, in-window entry — to hold the ITAR
/// capability. This is the directory-attested elevation of the self-declared
/// `seller.itar` flag (caveat 3). Mirrors the TypeScript `orgHasCapability`.
fn org_has_itar(dir_json: &str, org_id: &str, at_ms: i64) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(dir_json) else {
        return false;
    };
    let Some(entries) = v.get("entries").and_then(Value::as_array) else {
        return false;
    };
    entries.iter().any(|e| {
        e.get("org_id").and_then(Value::as_str) == Some(org_id)
            && entry_active_in_window(e, at_ms)
            && e.get("capabilities")
                .and_then(|c| c.get("itar"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
    })
}

/// Verify a seller's quote signature against the signed directory at `at_ms`.
/// True iff the quote carries an ML-DSA-87 signature, the directory verifies (and
/// is in-window) against `root_pk_hex`, and the signature resolves to an active,
/// in-window entry whose org matches `seller.org_id` and whose key verifies the
/// canonical quote body (the quote with its own `sig` removed). Mirrors the
/// TypeScript `verifyQuoteSignature`; the canonical body is built from the raw
/// JSON field set, so it matches the bytes the TS reference signed.
pub fn verify_quote_signature(
    quote_json: &str,
    dir_json: &str,
    root_pk_hex: &str,
    at_ms: i64,
) -> bool {
    if !verify_directory(dir_json, root_pk_hex, at_ms) {
        return false;
    }
    let Ok(mut v) = serde_json::from_str::<Value>(quote_json) else {
        return false;
    };
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    let Some(sig) = obj.get("sig").and_then(Value::as_object).cloned() else {
        return false;
    };
    if sig.get("alg").and_then(Value::as_str) != Some(SIG_ALG) {
        return false;
    }
    let (Some(kid), Some(sig_hex)) = (
        sig.get("kid").and_then(Value::as_str).map(str::to_string),
        sig.get("sig").and_then(Value::as_str).map(str::to_string),
    ) else {
        return false;
    };
    let Some(seller_org) = obj
        .get("seller")
        .and_then(|s| s.get("org_id"))
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return false;
    };
    obj.remove("sig");
    let Ok(canonical) = canonical_json(&v) else {
        return false;
    };
    match directory_entry_by_kid(dir_json, &kid, at_ms) {
        Some((org, pk)) => org == seller_org && verify_body(DOMAIN_QUOTE, &canonical, &sig_hex, &pk),
        None => false,
    }
}

/// ITAR gate elevated to directory attestation (caveat 3). None if the quote is
/// allowed; Some(reason) if refused. An ITAR traveler's seller must hold the ITAR
/// capability in a directory that itself verifies against the trust root — not
/// merely self-declare `seller.itar`. Fails closed (Some) on any malformed input.
/// Mirrors the TypeScript `itarAttestationBlocker`.
pub fn itar_attestation_blocker(
    traveler_json: &str,
    quote_json: &str,
    dir_json: &str,
    root_pk_hex: &str,
    at_ms: i64,
) -> Option<String> {
    let Ok(t) = serde_json::from_str::<Value>(traveler_json) else {
        return Some("ITAR gate: traveler does not parse".into());
    };
    if !t.get("itar").and_then(Value::as_bool).unwrap_or(false) {
        return None; // a non-ITAR traveler imposes no gate
    }
    if !verify_directory(dir_json, root_pk_hex, at_ms) {
        return Some("ITAR traveler: key directory does not verify against the trust root".into());
    }
    let Ok(q) = serde_json::from_str::<Value>(quote_json) else {
        return Some("ITAR gate: quote does not parse".into());
    };
    let Some(seller_org) = q
        .get("seller")
        .and_then(|s| s.get("org_id"))
        .and_then(Value::as_str)
    else {
        return Some("ITAR traveler: seller has no org_id to attest against the directory".into());
    };
    if !org_has_itar(dir_json, seller_org, at_ms) {
        return Some("ITAR traveler: seller is not attested for ITAR in the directory".into());
    }
    None
}

/// Verify a signed one-time prekey bundle (JSON) against the signed directory at
/// `at_ms`: the directory verifies against the root, the bundle's signing kid
/// resolves (active, in-window) to an entry whose org equals the bundle's org_id,
/// the bundle's own [issued_at, valid_until) covers at_ms, and the ML-DSA
/// signature over the canonical body (bundle minus its own sig) checks out. False
/// on any failure. Mirrors the TypeScript verifyPrekeyBundle.
pub fn verify_prekey_bundle(bundle_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    let Ok(mut v) = serde_json::from_str::<Value>(bundle_json) else {
        return false;
    };
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    if obj.get("spec").and_then(Value::as_str) != Some(PREKEY_BUNDLE_SPEC) {
        return false;
    }
    if obj.get("enc_alg").and_then(Value::as_str) != Some("ML-KEM-1024") {
        return false;
    }
    if !verify_directory(dir_json, root_pk_hex, at_ms) {
        return false;
    }
    let issued = obj
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(crate::rfc3339_millis);
    let until = obj
        .get("valid_until")
        .and_then(Value::as_str)
        .and_then(crate::rfc3339_millis);
    let (Some(issued), Some(until)) = (issued, until) else {
        return false;
    };
    if !(issued <= at_ms && at_ms < until) {
        return false;
    }
    let Some(org_id) = obj.get("org_id").and_then(Value::as_str).map(str::to_string) else {
        return false;
    };
    let Some(kid) = obj.get("kid").and_then(Value::as_str).map(str::to_string) else {
        return false;
    };
    let Some(sig) = obj.remove("sig").and_then(|s| s.as_str().map(str::to_string)) else {
        return false;
    };
    let Ok(canonical) = canonical_json(&v) else {
        return false;
    };
    match directory_entry_by_kid(dir_json, &kid, at_ms) {
        Some((entry_org, pk)) => entry_org == org_id && verify_body(DOMAIN_PREKEYS, &canonical, &sig, &pk),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_separation() {
        let (pk, sk) = keypair_from_seed(&[7u8; 32]);
        let body = r#"{"a":1}"#;
        let sig = sign_body(DOMAIN_TRAVELER, body, &sk);
        assert!(verify_body(DOMAIN_TRAVELER, body, &sig, &pk));
        // tampered body, wrong domain, wrong key all fail
        assert!(!verify_body(DOMAIN_TRAVELER, r#"{"a":2}"#, &sig, &pk));
        assert!(!verify_body(DOMAIN_QUOTE, body, &sig, &pk));
        let (pk2, _) = keypair_from_seed(&[9u8; 32]);
        assert!(!verify_body(DOMAIN_TRAVELER, body, &sig, &pk2));
        // malformed inputs are false, never panic
        assert!(!verify_body(DOMAIN_TRAVELER, body, "zz", &pk));
        assert!(!verify_body(DOMAIN_TRAVELER, body, &sig, "00"));
    }

    #[test]
    fn signing_is_deterministic() {
        let (_, sk) = keypair_from_seed(&[3u8; 32]);
        let a = sign_body(DOMAIN_QUOTE, r#"{"x":9}"#, &sk);
        let b = sign_body(DOMAIN_QUOTE, r#"{"x":9}"#, &sk);
        assert_eq!(a, b);
    }
}
