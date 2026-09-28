//! Replays the committed cross-implementation fuzz corpus (conformance/fuzz),
//! generated from the TypeScript reference (sim/corpus.ts). For each document the
//! Rust core recomputes the verdict — does it parse, what does it hash to, what
//! level is it, which quotes bind — and it must match the reference verdict stored
//! alongside it. This is the frozen, Node-free half of the cross-implementation
//! differential: agreement here is agreement between two independent codebases.

use std::fs;
use std::path::PathBuf;

use secure_job_envelope::check_verdict;
use serde_json::Value;

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fuzz")
}

#[test]
fn fuzz_corpus_verdicts_match_the_reference() {
    let dir = fuzz_dir();
    let travelers = fs::read_to_string(dir.join("travelers.jsonl")).expect("travelers.jsonl");
    let expected = fs::read_to_string(dir.join("expected.jsonl")).expect("expected.jsonl");

    let docs: Vec<&str> = travelers.lines().filter(|l| !l.trim().is_empty()).collect();
    let exps: Vec<&str> = expected.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(docs.len(), exps.len(), "corpus line counts differ");
    assert!(docs.len() >= 100, "corpus is unexpectedly small: {}", docs.len());

    let mut mismatches = 0usize;
    for (i, (doc, exp)) in docs.iter().zip(exps.iter()).enumerate() {
        let got: Value = serde_json::from_str(&check_verdict(doc)).expect("rust verdict json");
        let want: Value = serde_json::from_str(exp).expect("expected verdict json");
        if got != want {
            mismatches += 1;
            if mismatches <= 5 {
                eprintln!("corpus line {i} diverged\n  doc:  {doc}\n  want: {want}\n  got:  {got}");
            }
        }
    }
    assert_eq!(
        mismatches, 0,
        "{mismatches} of {} corpus verdicts diverged from the TypeScript reference",
        docs.len()
    );
}
