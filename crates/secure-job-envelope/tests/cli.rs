//! The command-line tool's contract: what it prints and, above all, how it EXITS —
//! scripts gate on the exit status (`envelope verify … && deploy`).
//!
//!   0  success (`check`: a verdict was printed; `verify`: the traveler IS verified)
//!   1  an input could not be read
//!   2  usage error, or refused / not verified

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn conformance() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn envelope(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_envelope")).args(args).output().expect("run envelope")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exit code")
}

/// The signed-award vector, written out as the three files `verify` takes. Returns
/// (dir, traveler value, at) — files: traveler.json, directory.json, root.hex.
fn award_fixture(tag: &str) -> (PathBuf, Value, String) {
    let v: Value =
        serde_json::from_str(&fs::read_to_string(conformance().join("signatures/signed-award.json")).unwrap()).unwrap();
    let dir = std::env::temp_dir().join(format!("sje-cli-{}-{tag}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("traveler.json"), serde_json::to_string(&v["traveler"]).unwrap()).unwrap();
    fs::write(dir.join("directory.json"), serde_json::to_string(&v["directory"]).unwrap()).unwrap();
    fs::write(dir.join("root.hex"), format!("{}\n", v["root_public_key_hex"].as_str().unwrap())).unwrap();
    (dir, v["traveler"].clone(), "2027-01-01T00:00:00.000Z".to_string())
}

fn verify(dir: &PathBuf, traveler: &str, at: &str) -> Output {
    envelope(&[
        "verify",
        dir.join(traveler).to_str().unwrap(),
        "--directory",
        dir.join("directory.json").to_str().unwrap(),
        "--root-file",
        dir.join("root.hex").to_str().unwrap(),
        "--at",
        at,
    ])
}

fn report(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("verify prints one JSON report")
}

#[test]
fn an_unknown_or_missing_command_fails() {
    // `envelope verfy f && echo TRUSTED` must not print TRUSTED. (An unknown command
    // once printed usage and exited 0.)
    for args in [&["verfy", "x.json"][..], &["sign"][..], &[][..]] {
        let out = envelope(args);
        assert_eq!(code(&out), 2, "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: nothing on stdout");
    }
    assert_eq!(code(&envelope(&["help"])), 0);
}

#[test]
fn verify_exits_zero_only_for_a_verified_traveler() {
    let (dir, traveler, at) = award_fixture("ok");
    let out = verify(&dir, "traveler.json", &at);
    let r = report(&out);
    assert_eq!(code(&out), 0, "{r}");
    assert_eq!(r["verified"], true);
    assert_eq!(r["authorship"][0]["org_id"], "org_northline");
    assert_eq!(r["award"]["ok"], true);

    // The same traveler with the ship-to redirected: the award no longer verifies.
    let mut forged = traveler.clone();
    forged["ship_to"]["line1"] = "1 Elsewhere Road".into();
    fs::write(dir.join("forged.json"), serde_json::to_string(&forged).unwrap()).unwrap();
    let out = verify(&dir, "forged.json", &at);
    let r = report(&out);
    assert_eq!(code(&out), 2, "{r}");
    assert_eq!(r["verified"], false);
    assert_eq!(r["award"]["reason"], "signature does not verify");

    // An award with its signature removed is a failure, not "nothing to check".
    let mut unsigned = traveler.clone();
    unsigned["award"].as_object_mut().unwrap().remove("sig");
    fs::write(dir.join("unsigned.json"), serde_json::to_string(&unsigned).unwrap()).unwrap();
    let out = verify(&dir, "unsigned.json", &at);
    assert_eq!(code(&out), 2);
    assert_eq!(report(&out)["award"]["reason"], "award is present but not signed by the buyer");

    // No signatures at all: not verified.
    let mut bare = traveler;
    bare.as_object_mut().unwrap().remove("signatures");
    fs::write(dir.join("bare.json"), serde_json::to_string(&bare).unwrap()).unwrap();
    let out = verify(&dir, "bare.json", &at);
    assert_eq!(code(&out), 2);
    assert_eq!(report(&out)["authorship"], serde_json::json!([]));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_trusts_only_the_root_and_the_time_it_is_given() {
    let (dir, _, at) = award_fixture("trust");
    // Outside the directory's own window.
    let out = verify(&dir, "traveler.json", "2031-01-01T00:00:00.000Z");
    assert_eq!(code(&out), 2);
    assert_eq!(report(&out)["authorship"][0]["reason"], "directory does not verify against the trust root");
    // A different root.
    fs::write(dir.join("root.hex"), "00".repeat(2592)).unwrap();
    let out = verify(&dir, "traveler.json", &at);
    assert_eq!(code(&out), 2);
    assert_eq!(report(&out)["verified"], false);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_usage_and_unreadable_inputs() {
    let (dir, _, at) = award_fixture("usage");
    let t = dir.join("traveler.json");
    let d = dir.join("directory.json");
    let r = dir.join("root.hex");
    let (t, d, r) = (t.to_str().unwrap(), d.to_str().unwrap(), r.to_str().unwrap());
    // usage errors: 2, nothing on stdout (so no report can be mistaken for a verdict)
    for args in [
        &["verify", t][..],
        &["verify", t, "--directory", d][..],
        &["verify", t, "--directory", d, "--root-file", r, "--root", "00"][..],
        &["verify", t, "--directory", d, "--root-file", r, "--at", "yesterday"][..],
        &["verify", t, "--directory", d, "--root-file", r, "--strict"][..],
        &["verify", t, t, "--directory", d, "--root-file", r][..],
        &["verify", "--directory", d, "--root-file", r][..],
    ] {
        let out = envelope(args);
        assert_eq!(code(&out), 2, "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: nothing on stdout");
    }
    // an unreadable input: 1
    let out = envelope(&["verify", "/nonexistent/traveler.json", "--directory", d, "--root-file", r, "--at", &at]);
    assert_eq!(code(&out), 1);
    assert!(out.stdout.is_empty());
    // a traveler that is not a traveler: a report, not verified
    fs::write(dir.join("junk.json"), "{\"itar\":true}").unwrap();
    let out = verify(&dir, "junk.json", &at);
    assert_eq!(code(&out), 2);
    assert_eq!(report(&out)["authorship"][0]["reason"], "not a valid traveler");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn check_and_hash_keep_their_contract() {
    let good = conformance().join("travelers/l0-bracket.json");
    let out = envelope(&["check", good.to_str().unwrap()]);
    assert_eq!(code(&out), 0);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["accept"], true);
    let bad = conformance().join("travelers/reject/byte-order-mark.json");
    let out = envelope(&["check", bad.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "check always prints a verdict");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["accept"], false);
    // hash / level REFUSE with a non-zero status.
    assert_eq!(code(&envelope(&["hash", bad.to_str().unwrap()])), 2);
    assert_eq!(code(&envelope(&["hash", good.to_str().unwrap()])), 0);
    assert_eq!(code(&envelope(&["hash", "/nonexistent.json"])), 1);
}
