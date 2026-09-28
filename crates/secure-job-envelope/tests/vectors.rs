//! Conformance vector runner (Rust side).
//! The same files are independently verified by the TypeScript
//! implementation (src/lib/traveler/vectors.test.ts); agreement across both
//! is the cross-implementation proof. See conformance/README.md.

use secure_job_envelope::{canonical_json, level, traveler_hash, parse_traveler};
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::fs;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

// Fixed evaluation instants (Unix ms) for the directory validity-window checks.
// The signature vectors' directory runs 2026-01-01 .. 2030-01-01.
const AT_MS_2027: i64 = 1_798_761_600_000; // within the window
const AT_MS_2025: i64 = 1_748_736_000_000; // before issued_at
const AT_MS_2031: i64 = 1_924_992_000_000; // after valid_until

#[test]
fn canonical_valid_vectors_match_bytes_and_hash() {
    let raw = fs::read_to_string(conformance_dir().join("canonical.json")).unwrap();
    let doc: Value = serde_json::from_str(&raw).unwrap();
    let valid = doc["valid"].as_array().expect("valid array");
    assert!(!valid.is_empty());
    for case in valid {
        let name = case["name"].as_str().unwrap();
        let value = &case["value"];
        let expected_canonical = case["canonical"].as_str().unwrap();
        let expected_hash = case["sha384"].as_str().unwrap();
        let got = canonical_json(value).unwrap_or_else(|e| panic!("{name}: refused: {e}"));
        assert_eq!(got, expected_canonical, "canonical bytes: {name}");
        let digest = Sha384::digest(got.as_bytes());
        assert_eq!(
            format!("sha384:{}", hex::encode(digest)),
            expected_hash,
            "hash: {name}"
        );
    }
}

#[test]
fn canonical_invalid_vectors_are_refused() {
    let raw = fs::read_to_string(conformance_dir().join("canonical.json")).unwrap();
    let doc: Value = serde_json::from_str(&raw).unwrap();
    let invalid = doc["invalid"].as_array().expect("invalid array");
    assert!(!invalid.is_empty());
    for case in invalid {
        let name = case["name"].as_str().unwrap();
        assert!(
            canonical_json(&case["value"]).is_err(),
            "must refuse: {name}"
        );
    }
}

#[test]
fn traveler_vectors_match_expected_hash_and_level() {
    let dir = conformance_dir().join("travelers");
    let raw = fs::read_to_string(dir.join("expected.json")).unwrap();
    let expected: Value = serde_json::from_str(&raw).unwrap();
    let map = expected.as_object().expect("expected map");
    assert!(!map.is_empty());
    for (file, exp) in map {
        let json = fs::read_to_string(dir.join(file)).unwrap();
        let traveler = parse_traveler(&json).unwrap_or_else(|e| panic!("{file}: refused: {e}"));
        assert_eq!(
            traveler_hash(&traveler).unwrap(),
            exp["traveler_hash"].as_str().unwrap(),
            "hash: {file}"
        );
        assert_eq!(level(&traveler).code, exp["level"].as_str().unwrap(), "level: {file}");
    }
}

#[test]
fn signature_vector_matches_cross_language() {
    use secure_job_envelope::sign::{keypair_from_seed, sign_body, verify_body};
    let raw = fs::read_to_string(conformance_dir().join("signatures/traveler-sig.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let domain = v["domain"].as_str().unwrap();
    let body = v["canonical_body"].as_str().unwrap();
    let pk_hex = v["public_key_hex"].as_str().unwrap();
    let sig_hex = v["signature_hex"].as_str().unwrap();

    let seed_bytes = hex::decode(v["seed_hex"].as_str().unwrap()).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let (pk, sk) = keypair_from_seed(&seed);

    // Same public key and same deterministic signature bytes as the TS reference.
    assert_eq!(pk, pk_hex, "public key mismatch across implementations");
    assert_eq!(sign_body(domain, body, &sk), sig_hex, "signature bytes mismatch");
    // Verifies, and tampering / domain-swap fail.
    assert!(verify_body(domain, body, sig_hex, pk_hex));
    assert!(!verify_body(domain, &format!("{body} "), sig_hex, pk_hex));
    assert!(!verify_body("sje-sig/quote/0.1.0", body, sig_hex, pk_hex));
}

#[test]
fn directory_vector_verifies_cross_language() {
    use secure_job_envelope::sign::verify_directory;
    let raw = fs::read_to_string(conformance_dir().join("signatures/directory.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root_pk = v["root_public_key_hex"].as_str().unwrap();
    let dir_json = serde_json::to_string(&v["directory"]).unwrap();
    assert!(verify_directory(&dir_json, root_pk, AT_MS_2027), "directory must verify in-window");
    // tampering the directory body breaks the root signature
    let mut tampered = v["directory"].clone();
    tampered["entries"][1]["capabilities"]["itar"] = serde_json::json!(true);
    assert!(
        !verify_directory(&serde_json::to_string(&tampered).unwrap(), root_pk, AT_MS_2027),
        "tampered directory must fail"
    );
    assert!(!verify_directory(&dir_json, &"00".repeat(2592), AT_MS_2027), "wrong root key must fail");
    // H3: a directory evaluated outside its own [issued_at, valid_until) window is refused
    assert!(!verify_directory(&dir_json, root_pk, AT_MS_2025), "before issued_at must fail");
    assert!(!verify_directory(&dir_json, root_pk, AT_MS_2031), "after valid_until must fail");
}

#[test]
fn signed_traveler_vector_verifies_cross_language() {
    use secure_job_envelope::sign::verify_traveler_authorship;
    let raw = fs::read_to_string(conformance_dir().join("signatures/signed-traveler.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root_pk = v["root_public_key_hex"].as_str().unwrap();
    let dir_json = serde_json::to_string(&v["directory"]).unwrap();
    let traveler_json = serde_json::to_string(&v["traveler"]).unwrap();
    assert!(
        verify_traveler_authorship(&traveler_json, &dir_json, root_pk, AT_MS_2027),
        "buyer authorship must verify end to end"
    );
    // bumping the hashed body (revision) breaks the authorship signature
    let mut tampered = v["traveler"].clone();
    tampered["revision"] = serde_json::json!(tampered["revision"].as_i64().unwrap() + 1);
    assert!(!verify_traveler_authorship(
        &serde_json::to_string(&tampered).unwrap(),
        &dir_json,
        root_pk,
        AT_MS_2027
    ));
    // a broken directory (wrong root key) fails
    assert!(!verify_traveler_authorship(&traveler_json, &dir_json, &"00".repeat(2592), AT_MS_2027));
    // H2: an author that names no org_id is refused (matches the TypeScript verifier)
    let mut no_org = v["traveler"].clone();
    no_org["buyer"].as_object_mut().unwrap().remove("org_id");
    assert!(
        !verify_traveler_authorship(&serde_json::to_string(&no_org).unwrap(), &dir_json, root_pk, AT_MS_2027),
        "an unbound author (no org_id) must be refused"
    );
}

#[test]
fn signed_quote_vector_verifies_cross_language() {
    use secure_job_envelope::sign::{itar_attestation_blocker, verify_quote_signature};
    let raw = fs::read_to_string(conformance_dir().join("signatures/signed-quote.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root_pk = v["root_public_key_hex"].as_str().unwrap();
    let at = v["at_ms"].as_i64().unwrap();
    let dir_json = serde_json::to_string(&v["directory"]).unwrap();
    let quote_json = serde_json::to_string(&v["quote"]).unwrap();

    // Seller quote signature verifies against the directory (same canonical bytes as TS).
    assert!(
        verify_quote_signature(&quote_json, &dir_json, root_pk, at),
        "seller quote signature must verify"
    );
    // Tampering the quote body breaks the signature.
    let mut tampered = v["quote"].clone();
    tampered["lead_time_days"] = serde_json::json!(999);
    assert!(!verify_quote_signature(
        &serde_json::to_string(&tampered).unwrap(),
        &dir_json,
        root_pk,
        at
    ));
    // Directory-attested ITAR gate: org_huron is attested -> allowed; a non-attested
    // seller org -> blocked. Parity with the TypeScript itarAttestationBlocker.
    let itar_traveler = r#"{"itar":true}"#;
    assert!(
        itar_attestation_blocker(itar_traveler, &quote_json, &dir_json, root_pk, at).is_none(),
        "attested ITAR seller must pass the gate"
    );
    let mut summit = v["quote"].clone();
    summit["seller"]["org_id"] = serde_json::json!("org_summitfab");
    assert!(
        itar_attestation_blocker(
            itar_traveler,
            &serde_json::to_string(&summit).unwrap(),
            &dir_json,
            root_pk,
            at
        )
        .is_some(),
        "a non-attested ITAR seller must be blocked"
    );
}

#[test]
fn envelope_vector_roundtrips_cross_language() {
    use secure_job_envelope::envelope::{enc_kid, open, seal_deterministic_fields};
    let raw = fs::read_to_string(conformance_dir().join("signatures/envelope.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let kid = v["recipient"]["kid"].as_str().unwrap();
    let pk_hex = v["recipient"]["public_key_hex"].as_str().unwrap();
    // The recipient kid is derived from its ML-KEM public key, identically to TS (M3).
    assert_eq!(enc_kid(pk_hex).as_deref(), Some(kid), "enc_kid derivation must match TS");
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&hex::decode(v["recipient"]["seed_hex"].as_str().unwrap()).unwrap());
    let d = &v["determinism"];
    let cek: [u8; 32] = hex::decode(d["cek_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let pn: [u8; 12] = hex::decode(d["payload_nonce_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let coins: [u8; 32] = hex::decode(d["coins_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let wn: [u8; 12] = hex::decode(d["wrap_nonce_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let plaintext = v["plaintext_utf8"].as_str().unwrap().as_bytes();

    // Rust re-seals to byte-identical ciphertext fields as the TS reference.
    let (kem_ct, wrapped, payload) = seal_deterministic_fields(plaintext, &seed, kid, &cek, &pn, &coins, &wn);
    assert_eq!(kem_ct, v["envelope"]["recipients"][0]["kem_ct"].as_str().unwrap());
    assert_eq!(wrapped, v["envelope"]["recipients"][0]["wrapped_cek"].as_str().unwrap());
    assert_eq!(payload, v["envelope"]["payload"].as_str().unwrap());

    // Rust opens the TS-sealed envelope back to the plaintext.
    let envelope_json = serde_json::to_string(&v["envelope"]).unwrap();
    assert_eq!(open(&envelope_json, kid, &seed).as_deref(), Some(plaintext));
    assert!(open(&envelope_json, "no-such-kid", &seed).is_none());
}

#[test]
fn expired_entry_directory_enforces_window_cross_language() {
    use secure_job_envelope::sign::verify_traveler_authorship;
    let raw =
        fs::read_to_string(conformance_dir().join("signatures/directory-expired-entry.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root_pk = v["root_public_key_hex"].as_str().unwrap();
    let dir_json = serde_json::to_string(&v["directory"]).unwrap();
    let traveler_json = serde_json::to_string(&v["traveler"]).unwrap();
    let valid_at = v["valid_at_ms"].as_i64().unwrap();
    let expired_at = v["expired_at_ms"].as_i64().unwrap();
    // Entry in window -> authentic; entry expired (directory still valid) -> refused (H1).
    assert!(
        verify_traveler_authorship(&traveler_json, &dir_json, root_pk, valid_at),
        "authorship must verify while the signer entry is in window"
    );
    assert!(
        !verify_traveler_authorship(&traveler_json, &dir_json, root_pk, expired_at),
        "authorship must be refused once the signer entry expires"
    );
}

#[test]
fn prekey_bundle_vector_verifies_cross_language() {
    use secure_job_envelope::sign::verify_prekey_bundle;
    let raw = fs::read_to_string(conformance_dir().join("signatures/prekey-bundle.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root_pk = v["root_public_key_hex"].as_str().unwrap();
    let at = v["at_ms"].as_i64().unwrap();
    let dir_json = serde_json::to_string(&v["directory"]).unwrap();
    let bundle_json = serde_json::to_string(&v["bundle"]).unwrap();
    assert!(
        verify_prekey_bundle(&bundle_json, &dir_json, root_pk, at),
        "prekey bundle must verify against the directory"
    );
    // tampering a prekey breaks the org's signature over the bundle
    let mut tampered = v["bundle"].clone();
    tampered["prekeys"][0]["public_key"] = serde_json::json!("00");
    assert!(!verify_prekey_bundle(&serde_json::to_string(&tampered).unwrap(), &dir_json, root_pk, at));
    // the bundle's own window is enforced: 2028 is past its 2027 valid_until,
    // though the directory (to 2030) is still valid
    const AT_MS_2028: i64 = 1_830_297_600_000;
    assert!(
        !verify_prekey_bundle(&bundle_json, &dir_json, root_pk, AT_MS_2028),
        "an out-of-window bundle must fail even while the directory is valid"
    );
    // wrong root key
    assert!(!verify_prekey_bundle(&bundle_json, &dir_json, &"00".repeat(2592), at));
}

#[test]
fn reject_vectors_are_refused_at_parse() {
    let dir = conformance_dir().join("travelers/reject");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let json = fs::read_to_string(&path).unwrap();
        assert!(
            parse_traveler(&json).is_err(),
            "must refuse: {}",
            path.display()
        );
        count += 1;
    }
    assert!(count >= 3, "reject vectors present");
}
