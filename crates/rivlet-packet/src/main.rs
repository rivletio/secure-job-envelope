use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;

use rivlet_packet::{level, packet_hash, parse_packet};

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    match cmd {
        "hash" | "level" => {
            let json = read_input(args.get(2).map(String::as_str));
            let packet = parse_packet(&json).unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(2);
            });
            if cmd == "hash" {
                match packet_hash(&packet) {
                    Ok(h) => println!("{h}"),
                    Err(e) => {
                        eprintln!("{e}");
                        process::exit(2);
                    }
                }
            } else {
                let l = level(&packet);
                println!("{} {}", l.code, l.name);
            }
        }
        _ => {
            eprintln!("rivlet-packet 0.0.1");
            eprintln!("  rivlet-packet hash [packet.json]");
            eprintln!("  rivlet-packet level [packet.json]");
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
