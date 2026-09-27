//! Post-quantum authorship signatures — CNSA 2.0 profile (ML-DSA-87, FIPS 204).
//!
//! Mirrors `src/lib/traveler/signature.ts` byte-for-byte: the signed message is
//! `domain ‖ 0x00 ‖ canonical_body`, signed with the deterministic ML-DSA
//! variant (rnd = 0), so a signature produced by the TypeScript reference
//! verifies here and vice versa. The shared `conformance/signatures/*` vectors
//! pin this agreement across the two independent codebases.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, SigningKey, VerifyingKey, B32,
};

pub const SIG_ALG: &str = "ML-DSA-87";
pub const DOMAIN_TRAVELER: &str = "sje-sig/traveler/0.1.0";
pub const DOMAIN_QUOTE: &str = "sje-sig/quote/0.1.0";
pub const DOMAIN_DIRECTORY: &str = "sje-sig/directory/0.1.0";

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
