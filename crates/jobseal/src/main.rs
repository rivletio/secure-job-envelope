use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;

use jobseal::{level, traveler_hash, parse_traveler};

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
        _ => {
            eprintln!("jobseal 0.0.1");
            eprintln!("  jobseal hash [traveler.json]");
            eprintln!("  jobseal level [traveler.json]");
            eprintln!("stdin is used when no file is given.");
        }
    }
}

fn read_input(path: Option<&str>) -> String {
    match path {
        Some("-") | None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).expect("stdin");
            buf
        }
        Some(p) => fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("{p}: {e}");
            process::exit(1);
        }),
    }
}
