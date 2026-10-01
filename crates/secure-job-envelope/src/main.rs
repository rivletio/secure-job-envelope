use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;

use secure_job_envelope::{check_verdict, level, parse_traveler, traveler_hash};

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    match cmd {
        "hash" | "level" => {
            let json = read_input(args.get(2).map(String::as_str));
            let traveler = parse_traveler(&json).unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(2);
            });
            if cmd == "hash" {
                match traveler_hash(&traveler) {
                    Ok(h) => println!("{h}"),
                    Err(e) => {
                        eprintln!("{e}");
                        process::exit(2);
                    }
                }
            } else {
                let l = level(&traveler);
                println!("{} {}", l.code, l.name);
            }
        }
        // A single machine-readable verdict for the cross-implementation
        // differential (sim/differential.ts): does this document parse, what does
        // it hash to, what level is it, and which quotes bind? Emitting all four in
        // one compact JSON line lets the fuzzer compare the two implementations
        // with a single process spawn per input. Errors are never included in the
        // verdict — their wording differs by design; only the decisions are compared.
        "check" => {
            let json = read_input(args.get(2).map(String::as_str));
            println!("{}", check_verdict(&json));
        }
        _ => {
            eprintln!("envelope (SJE) 0.1.0");
            eprintln!("  envelope hash [traveler.json]");
            eprintln!("  envelope level [traveler.json]");
            eprintln!("  envelope check [traveler.json]   # JSON verdict for the differential");
            eprintln!("stdin is used when no file is given.");
        }
    }
}

fn read_input(path: Option<&str>) -> String {
    match path {
        Some("-") | None => {
            let mut buf = String::new();
            // No panic on non-UTF-8 or a read error — report and exit cleanly.
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("stdin: {e}");
                process::exit(1);
            }
            buf
        }
        Some(p) => fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("{p}: {e}");
            process::exit(1);
        }),
    }
}
