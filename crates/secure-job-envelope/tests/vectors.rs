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
fn signed_award_vector_verifies_cross_language() {
    use secure_job_envelope::sign::verify_award_signature;
    let raw = fs::read_to_string(conformance_dir().join("signatures/signed-award.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root_pk = v["root_public_key_hex"].as_str().unwrap();
    let at = v["at_ms"].as_i64().unwrap();
    let dir_json = serde_json::to_string(&v["directory"]).unwrap();
    let traveler_json = serde_json::to_string(&v["traveler"]).unwrap();

    // The buyer's award signature verifies end to end (same canonical bytes as TS).
    assert!(
        verify_award_signature(&traveler_json, &dir_json, root_pk, at),
        "buyer award signature must verify"
    );
    // Altering the ship-to breaks the award signature (the altered-destination case).
    let mut tampered = v["traveler"].clone();
    tampered["ship_to"]["postal"] = serde_json::json!("00000");
    assert!(
        !verify_award_signature(&serde_json::to_string(&tampered).unwrap(), &dir_json, root_pk, at),
        "an altered ship-to must fail the award signature"
    );
    // Changing the awarded quantity breaks it.
    let mut reqty = v["traveler"].clone();
    reqty["award"]["qty"] = serde_json::json!(reqty["award"]["qty"].as_i64().unwrap() + 1);
    assert!(!verify_award_signature(&serde_json::to_string(&reqty).unwrap(), &dir_json, root_pk, at));
    // Bumping the hashed body (revision) breaks the binding to the exact revision.
    let mut rev = v["traveler"].clone();
    rev["revision"] = serde_json::json!(rev["revision"].as_i64().unwrap() + 1);
    assert!(!verify_award_signature(&serde_json::to_string(&rev).unwrap(), &dir_json, root_pk, at));
    // An unsigned award is refused (present-but-unsigned fails closed).
    let mut unsigned = v["traveler"].clone();
    unsigned["award"].as_object_mut().unwrap().remove("sig");
    assert!(
        !verify_award_signature(&serde_json::to_string(&unsigned).unwrap(), &dir_json, root_pk, at),
        "an unsigned award must be refused"
    );
    // A non-buyer signer (the award sig's kid points at a different org) is refused.
    let mut wrong_org = v["traveler"].clone();
    wrong_org["award"]["sig"]["kid"] = serde_json::json!("summit-2026");
    assert!(
        !verify_award_signature(&serde_json::to_string(&wrong_org).unwrap(), &dir_json, root_pk, at),
        "an award signed by a non-buyer org must be refused"
    );
    // The hardening: a swapped unit price on the awarded quote breaks the award signature,
    // because the awarded quote no longer hashes to the buyer-signed award.quote_hash — even
    // though that quote is unsigned here. This is the completeness gap the binding closes.
    let mut swapped = v["traveler"].clone();
    {
        let qid = swapped["award"]["quote_id"].as_str().unwrap().to_string();
        let quotes = swapped["quotes"].as_array_mut().unwrap();
        let q = quotes
            .iter_mut()
            .find(|q| q["quote_id"].as_str() == Some(&qid))
            .unwrap();
        let unit = q["pricing"]["lines"][0]["unit"].as_i64().unwrap();
        q["pricing"]["lines"][0]["unit"] = serde_json::json!(unit + 1);
    }
    assert!(
        !verify_award_signature(&serde_json::to_string(&swapped).unwrap(), &dir_json, root_pk, at),
        "a swapped unit price on the awarded quote must fail the award signature"
    );
    // Hard failure: stripping the awarded quote from `quotes` leaves nothing to re-verify the
    // priced content against, so the award is refused (not a soft 'unavailable' accept).
    let mut stripped = v["traveler"].clone();
    stripped["quotes"] = serde_json::json!([]);
    assert!(
        !verify_award_signature(&serde_json::to_string(&stripped).unwrap(), &dir_json, root_pk, at),
        "a stripped awarded quote must fail the award signature (hard fail)"
    );
    // A broken directory (wrong root key) fails.
    assert!(!verify_award_signature(&traveler_json, &dir_json, &"00".repeat(2592), at));
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
    let mut itar_doc: Value =
        serde_json::from_str(&fs::read_to_string(conformance_dir().join("travelers/l0-bracket.json")).unwrap())
            .unwrap();
    itar_doc["itar"] = serde_json::json!(true);
    let itar_traveler = &serde_json::to_string(&itar_doc).unwrap();
    assert!(
        itar_attestation_blocker(itar_traveler, &quote_json, &dir_json, root_pk, at).is_none(),
        "attested ITAR seller must pass the gate"
    );
    // A traveler that does not parse is refused, never read as "not ITAR" (the gate
    // used to fail open on `{"itar":1}` and on a fragment like `{"itar":true}`).
    for malformed in [r#"{"itar":true}"#, r#"{"itar":1}"#, "[]", "not json"] {
        assert_eq!(
            itar_attestation_blocker(malformed, &quote_json, &dir_json, root_pk, at).as_deref(),
            Some("ITAR gate: not a valid traveler"),
            "{malformed}"
        );
    }
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
fn fs_envelope_vector_roundtrips_cross_language() {
    use secure_job_envelope::envelope::{open_fs, seal_fs_deterministic_fields};
    let raw = fs::read_to_string(conformance_dir().join("signatures/fs-envelope.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let kid = v["recipient"]["kid"].as_str().unwrap();
    let prekey_id = v["recipient"]["prekey_id"].as_str().unwrap();
    let mut static_seed = [0u8; 64];
    static_seed.copy_from_slice(&hex::decode(v["recipient"]["static_seed_hex"].as_str().unwrap()).unwrap());
    let mut onetime_seed = [0u8; 64];
    onetime_seed.copy_from_slice(&hex::decode(v["recipient"]["onetime_seed_hex"].as_str().unwrap()).unwrap());
    let d = &v["determinism"];
    let cek: [u8; 32] = hex::decode(d["cek_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let pn: [u8; 12] = hex::decode(d["payload_nonce_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let co: [u8; 32] = hex::decode(d["coins_onetime_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let cs: [u8; 32] = hex::decode(d["coins_static_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let wn: [u8; 12] = hex::decode(d["wrap_nonce_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let plaintext = v["plaintext_utf8"].as_str().unwrap().as_bytes();

    // Rust re-seals to byte-identical ciphertext fields as the TS reference.
    let (ct_ot, ct_id, wrapped, payload) = seal_fs_deterministic_fields(
        plaintext,
        &static_seed,
        &onetime_seed,
        kid,
        prekey_id,
        &cek,
        &pn,
        &co,
        &cs,
        &wn,
    );
    assert_eq!(ct_ot, v["envelope"]["recipients"][0]["kem_ct_onetime"].as_str().unwrap());
    assert_eq!(ct_id, v["envelope"]["recipients"][0]["kem_ct_static"].as_str().unwrap());
    assert_eq!(wrapped, v["envelope"]["recipients"][0]["wrapped_cek"].as_str().unwrap());
    assert_eq!(payload, v["envelope"]["payload"].as_str().unwrap());

    // Rust opens the TS-sealed envelope with both secret keys.
    let envelope_json = serde_json::to_string(&v["envelope"]).unwrap();
    assert_eq!(
        open_fs(&envelope_json, kid, &static_seed, &onetime_seed).as_deref(),
        Some(plaintext)
    );
    // wrong kid, and (forward secrecy) a missing/wrong one-time secret both fail.
    assert!(open_fs(&envelope_json, "no-such-kid", &static_seed, &onetime_seed).is_none());
    let wrong_ot = [0x77u8; 64];
    assert!(
        open_fs(&envelope_json, kid, &static_seed, &wrong_ot).is_none(),
        "without the one-time secret the envelope must not open (forward secrecy)"
    );
    // An appended malformed recipient (string kid, null prekey_id) must invalidate the
    // envelope. Previously the Rust open filtered on kid AND prekey_id (silently dropping
    // this entry) while TS filtered on kid only (keeping it), so the same bytes opened on
    // Rust but were rejected by TS — a cross-impl parity break plus recipient-set
    // malleability. Both implementations now fail closed on any malformed recipient entry.
    let mut tampered = v["envelope"].clone();
    tampered["recipients"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "kid": "deadbeefdeadbeef", "prekey_id": null }));
    assert!(
        open_fs(&serde_json::to_string(&tampered).unwrap(), kid, &static_seed, &onetime_seed).is_none(),
        "an appended malformed recipient must invalidate the FS envelope"
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
    // Each vector must be refused FOR THE REASON IT IS NAMED FOR. A vector refused for
    // some other defect proves nothing about its rule (itar-mismatch.json once carried
    // a fractional price, so it kept passing with the ITAR check deleted).
    // reject-reasons.json pins, per vector, a fragment each implementation's refusal
    // must mention; the TypeScript runner checks its own column of the same file.
    let reasons: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(conformance_dir().join("travelers/reject-reasons.json")).unwrap(),
    )
    .unwrap();
    let dir = conformance_dir().join("travelers/reject");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let expected = reasons[&name]["rs"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no reason declared in reject-reasons.json"));
        let json = fs::read_to_string(&path).unwrap();
        let err = match parse_traveler(&json) {
            Ok(_) => panic!("must refuse: {}", path.display()),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains(expected),
            "{name}: refused for the wrong reason — \"{err}\" does not mention \"{expected}\""
        );
        count += 1;
    }
    assert_eq!(
        count,
        reasons.as_object().unwrap().len(),
        "reject-reasons.json and the reject directory must list the same vectors"
    );
    assert!(count >= 3, "reject vectors present");
}

/// The shared envelope accept/reject cases (`signatures/envelope-cases.json`, generated by
/// `conformance/generate.ts`; the TypeScript runner replays the same file). The stage of a
/// reject case is checked, not just the refusal: a "shape" case must fail the shape check
/// itself — most of them would decrypt if that check were missing — and a "crypto" case
/// must PASS the shape check and then fail to open.
#[test]
fn envelope_cases_agree_with_the_reference() {
    use secure_job_envelope::envelope::{check_shape, open, open_fs};
    let raw = fs::read_to_string(conformance_dir().join("signatures/envelope-cases.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let plaintext = v["plaintext_utf8"].as_str().unwrap().as_bytes();
    let seed = |c: &Value, member: &str| -> [u8; 64] {
        hex::decode(c[member].as_str().unwrap()).unwrap().try_into().unwrap()
    };
    let try_open = |c: &Value| -> Option<Vec<u8>> {
        let (text, kid) = (c["text"].as_str().unwrap(), c["kid"].as_str().unwrap());
        if c.get("onetime_seed_hex").is_some() {
            open_fs(text, kid, &seed(c, "seed_hex"), &seed(c, "onetime_seed_hex"))
        } else {
            open(text, kid, &seed(c, "seed_hex"))
        }
    };

    let accept = v["accept"].as_array().unwrap();
    let reject = v["reject"].as_array().unwrap();
    assert!(accept.len() >= 5 && reject.len() >= 40, "the case file looks truncated");
    for c in accept {
        let name = c["name"].as_str().unwrap();
        assert_eq!(check_shape(c["text"].as_str().unwrap()), Ok(()), "accept {name}: shape");
        assert_eq!(try_open(c).as_deref(), Some(plaintext), "accept {name}: opens");
    }
    for c in reject {
        let name = c["name"].as_str().unwrap();
        let shape = check_shape(c["text"].as_str().unwrap());
        match c["stage"].as_str().unwrap() {
            "shape" => assert!(shape.is_err(), "reject {name}: must be refused by the shape check"),
            "crypto" => assert_eq!(shape, Ok(()), "reject {name}: must pass the shape check"),
            other => panic!("unknown stage {other}"),
        }
        assert!(try_open(c).is_none(), "reject {name}: must not open");
    }
}

/// The shared verification cases (`signatures/directory-cases.json`, `verify-cases.json`;
/// generated by `conformance/generate.ts`, replayed by the TypeScript runner too). They
/// pin what both implementations REFUSE and why: a document signed with another enrolled
/// org's real key, a revoked or expired signer, an award that binds nothing determinate,
/// a directory the root really signed but that is not well-formed. The refusal REASON is
/// part of every expectation, so a rule cannot be dropped without a case noticing.
mod verification_cases {
    use super::*;
    use secure_job_envelope::sign::{
        directory_shape, itar_attestation_blocker, prekey_bundle_shape, recipient_by_org, verify_directory,
        verify_prekey_bundle, verify_report, Check,
    };

    fn load(name: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(conformance_dir().join("signatures").join(name)).unwrap()).unwrap()
    }
    fn s<'a>(v: &'a Value, member: &str) -> &'a str {
        v[member].as_str().unwrap_or_else(|| panic!("case member {member} is not a string"))
    }
    /// The trust root a case is evaluated under (its own, or the file's default).
    fn root<'a>(case: &'a Value, file: &'a Value) -> &'a str {
        case.get("root").and_then(Value::as_str).unwrap_or_else(|| s(file, "root_public_key_hex"))
    }
    fn at(case: &Value) -> i64 {
        case["at_ms"].as_i64().unwrap()
    }
    /// The named directory, as JSON text.
    fn directory(dirs: &Value, case: &Value) -> String {
        let d = &dirs["directories"][s(case, "directory")];
        assert!(d.is_object(), "case names an unknown directory");
        serde_json::to_string(d).unwrap()
    }
    /// What a case pins about one check: who signed when it passes, why not when it fails.
    fn slim(c: Option<&Check>) -> Value {
        match c {
            None => Value::Null,
            Some(c) if c.ok => serde_json::json!({ "ok": true, "kid": c.kid, "org_id": c.org_id }),
            Some(c) => serde_json::json!({ "ok": false, "reason": c.reason }),
        }
    }

    #[test]
    fn directories_are_well_formed_then_trusted() {
        let f = load("directory-cases.json");
        let cases = f["directory_cases"].as_array().unwrap();
        assert!(cases.len() >= 35, "directory cases look truncated");
        for c in cases {
            let (name, text) = (s(c, "name"), s(c, "text"));
            assert_eq!(directory_shape(text).is_ok(), c["shape_ok"].as_bool().unwrap(), "{name}: shape");
            assert_eq!(
                verify_directory(text, root(c, &f), at(c)),
                c["verifies"].as_bool().unwrap(),
                "{name}: verifies"
            );
        }
    }

    #[test]
    fn prekey_bundles_are_well_formed_then_trusted() {
        let f = load("directory-cases.json");
        let cases = f["bundle_cases"].as_array().unwrap();
        assert!(cases.len() >= 13, "bundle cases look truncated");
        for c in cases {
            let (name, text) = (s(c, "name"), s(c, "text"));
            assert_eq!(prekey_bundle_shape(text).is_ok(), c["shape_ok"].as_bool().unwrap(), "{name}: shape");
            assert_eq!(
                verify_prekey_bundle(text, &directory(&f, c), root(c, &f), at(c)),
                c["verifies"].as_bool().unwrap(),
                "{name}: verifies"
            );
        }
    }

    #[test]
    fn recipient_resolution_ignores_entry_order() {
        let f = load("directory-cases.json");
        let cases = f["recipient_cases"].as_array().unwrap();
        assert!(cases.len() >= 10, "recipient cases look truncated");
        for c in cases {
            let got = recipient_by_org(&directory(&f, c), s(c, "org_id"), at(c))
                .map_or(Value::Null, |(kid, key)| serde_json::json!({ "kid": kid, "public_key": key }));
            assert_eq!(got, c["want"], "{}", s(c, "name"));
        }
    }

    #[test]
    fn travelers_verify_to_the_same_verdict_and_reason() {
        let dirs = load("directory-cases.json");
        let f = load("verify-cases.json");
        let cases = f["traveler_cases"].as_array().unwrap();
        assert!(cases.len() >= 30, "traveler cases look truncated");
        for c in cases {
            let r = verify_report(s(c, "traveler"), &directory(&dirs, c), root(c, &f), at(c));
            let got = serde_json::json!({
                "authorship": r.authorship.iter().map(|x| slim(Some(x))).collect::<Vec<_>>(),
                "award": slim(r.award.as_ref()),
                "quotes": r.quotes.iter()
                    .map(|(id, x)| serde_json::json!({ "quote_id": id, "check": slim(x.as_ref()) }))
                    .collect::<Vec<_>>(),
                "verified": r.verified(),
            });
            assert_eq!(got, c["want"], "{}", s(c, "name"));
        }
    }

    #[test]
    fn itar_gate_allows_or_refuses_for_the_stated_reason() {
        let dirs = load("directory-cases.json");
        let f = load("verify-cases.json");
        let cases = f["itar_cases"].as_array().unwrap();
        assert!(cases.len() >= 12, "itar cases look truncated");
        for c in cases {
            let got = itar_attestation_blocker(s(c, "traveler"), s(c, "quote"), &directory(&dirs, c), root(c, &f), at(c));
            assert_eq!(got.as_deref(), c["want"].as_str(), "{}", s(c, "name"));
        }
    }
}
