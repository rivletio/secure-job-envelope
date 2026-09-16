//! Conformance vector runner (Rust side).
//! The same files are independently verified by the TypeScript
//! implementation (src/lib/traveler/vectors.test.ts); agreement across both
//! is the cross-implementation proof. See conformance/README.md.

use opentraveler::{canonical_json, level, traveler_hash, parse_traveler};
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::fs;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

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
