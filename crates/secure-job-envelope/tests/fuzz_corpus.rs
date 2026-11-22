//! Replays the committed cross-implementation fuzz corpus (conformance/fuzz),
//! generated from the TypeScript reference (sim/corpus.ts). For each case the Rust
//! core recomputes the verdict — does it parse, what does it hash to, what level is
//! it, which quotes bind — and it must match the reference verdict in the manifest.
//! This is the frozen, Node-free half of the cross-implementation differential:
//! agreement here is agreement between two independent codebases. (The TypeScript
//! side replays the same files in sim/corpus.test.ts.)
//!
//! A case is its exact BYTES — `cases/<seed>.bin`, one file each, because some are
//! not UTF-8, start with a byte-order mark or end in a NUL. So the replay starts
//! from bytes, twice over: through the library (as an embedder would call it) and
//! through the `envelope check` CLI (what the live fuzzer drives).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use secure_job_envelope::{check_verdict, reject_verdict};
use serde_json::Value;
use sha2::{Digest, Sha384};

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fuzz")
}

struct Case {
    file: String,
    mutations: String,
    bytes: Vec<u8>,
    sha384: String,
    size: usize,
    expected: Value,
}

fn corpus() -> Vec<Case> {
    let dir = fuzz_dir();
    let manifest = fs::read_to_string(dir.join("manifest.jsonl")).expect("manifest.jsonl");
    let cases: Vec<Case> = manifest
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let entry: Value = serde_json::from_str(line).expect("manifest line is JSON");
            let file = entry["file"].as_str().expect("file").to_owned();
            let mutations: Vec<&str> =
                entry["mutations"].as_array().expect("mutations").iter().filter_map(Value::as_str).collect();
            Case {
                bytes: fs::read(dir.join(&file)).unwrap_or_else(|e| panic!("{file}: {e}")),
                mutations: if mutations.is_empty() { "none".into() } else { mutations.join(" + ") },
                sha384: entry["sha384"].as_str().expect("sha384").to_owned(),
                size: entry["bytes"].as_u64().expect("bytes") as usize,
                expected: entry["expected"].clone(),
                file,
            }
        })
        .collect();
    assert!(cases.len() >= 200, "corpus is unexpectedly small: {}", cases.len());
    cases
}

/// The verdict for a document held as bytes. `check_verdict` takes text, so a caller
/// with bytes must first decide what bytes that are not UTF-8 mean: a refusal — never
/// a lossy decode, which would turn them into U+FFFD and judge a different document.
/// (The size cap needs no separate step: `check_verdict` refuses text over 512 KiB.)
fn verdict_of(bytes: &[u8]) -> Value {
    let verdict = match std::str::from_utf8(bytes) {
        Ok(text) => check_verdict(text),
        Err(_) => reject_verdict(),
    };
    serde_json::from_str(&verdict).expect("verdict is JSON")
}

fn assert_all_match(what: &str, verdict: impl Fn(&Case) -> Value) {
    let cases = corpus();
    let mut mismatches = 0usize;
    for case in &cases {
        let got = verdict(case);
        if got != case.expected {
            mismatches += 1;
            if mismatches <= 5 {
                eprintln!(
                    "{} ({}) diverged {what}\n  want: {}\n  got:  {got}",
                    case.file, case.mutations, case.expected
                );
            }
        }
    }
    assert_eq!(
        mismatches,
        0,
        "{mismatches} of {} corpus verdicts diverged from the TypeScript reference {what}",
        cases.len()
    );
}

#[test]
fn fuzz_corpus_is_byte_for_byte_what_the_manifest_describes() {
    // A checkout that normalized line endings or re-encoded a case would still pass a
    // verdict replay on most cases; the digest catches it on every one.
    let cases = corpus();
    for case in &cases {
        assert_eq!(case.bytes.len(), case.size, "{}: size", case.file);
        let digest = format!("sha384:{}", hex::encode(Sha384::digest(&case.bytes)));
        assert_eq!(digest, case.sha384, "{}: bytes differ from the manifest", case.file);
    }
    // Every file in cases/ is in the manifest (a stray one would never be replayed).
    let mut on_disk: Vec<String> = fs::read_dir(fuzz_dir().join("cases"))
        .expect("cases/")
        .map(|e| format!("cases/{}", e.unwrap().file_name().to_string_lossy()))
        .collect();
    let mut listed: Vec<String> = cases.iter().map(|c| c.file.clone()).collect();
    on_disk.sort();
    listed.sort();
    assert_eq!(on_disk, listed, "conformance/fuzz/cases and manifest.jsonl list different files");
}

#[test]
fn fuzz_corpus_verdicts_match_the_reference() {
    assert_all_match("in the library", |case| verdict_of(&case.bytes));
}

#[test]
fn fuzz_corpus_verdicts_match_the_reference_through_the_cli() {
    // The same files, read by the binary itself: its own size cap, its own UTF-8
    // check. `check` must print a verdict and exit 0 whatever the bytes are.
    let dir = fuzz_dir();
    assert_all_match("through `envelope check`", |case| {
        let out = Command::new(env!("CARGO_BIN_EXE_envelope"))
            .arg("check")
            .arg(dir.join(&case.file))
            .output()
            .expect("run the envelope CLI");
        assert!(
            out.status.success(),
            "{}: `envelope check` exited {:?} without a verdict: {}",
            case.file,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{}: no verdict on stdout: {e}", case.file))
    });
}
