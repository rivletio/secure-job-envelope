use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::process;

use secure_job_envelope::sign::{self, Check, MAX_DIRECTORY_JSON_BYTES};
use secure_job_envelope::{
    check_verdict, level, parse_traveler, reject_verdict, traveler_hash, MAX_TRAVELER_JSON_BYTES,
};

/// Exit codes (stable; scripts may rely on them):
///   0  success (for `check`: a verdict was printed — read its `accept` field;
///      for `verify`: the traveler IS verified)
///   1  the input could not be read (missing file, I/O error)
///   2  usage error (unknown or missing command), or the document was refused
///      (for `verify`: NOT verified — the report on stdout says why)
const EXIT_IO: i32 = 1;
const EXIT_REFUSED: i32 = 2;

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(cmd) = args.get(1).map(String::as_str) else {
        usage(&mut io::stderr());
        process::exit(EXIT_REFUSED);
    };
    match cmd {
        "hash" | "level" => {
            let json = match read_input(args.get(2).map(String::as_str)) {
                Input::Text(s) => s,
                Input::TooLarge => refuse("input exceeds 512 KiB"),
                Input::NotUtf8 => refuse("input is not valid UTF-8"),
            };
            let traveler = parse_traveler(&json).unwrap_or_else(|e| refuse(&e.to_string()));
            if cmd == "hash" {
                match traveler_hash(&traveler) {
                    Ok(h) => println!("{h}"),
                    Err(e) => refuse(&e.to_string()),
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
        // An oversized or non-UTF-8 input is a refusal like any other, so it yields
        // the reject verdict (exit 0) rather than an error exit with no verdict.
        "check" => match read_input(args.get(2).map(String::as_str)) {
            Input::Text(json) => println!("{}", check_verdict(&json)),
            Input::TooLarge | Input::NotUtf8 => println!("{}", reject_verdict()),
        },
        "verify" => verify(&args[2..]),
        "help" | "--help" | "-h" => usage(&mut io::stdout()),
        // An unknown command MUST fail. It used to print usage and exit 0, so a
        // script gating on this tool — `envelope verify f && echo TRUSTED` — read a
        // mistyped or not-yet-existing command as success.
        _ => {
            eprintln!("envelope: unknown command {}", printable(cmd));
            usage(&mut io::stderr());
            process::exit(EXIT_REFUSED);
        }
    }
}

fn usage(out: &mut dyn io::Write) {
    let _ = writeln!(
        out,
        "envelope (SJE) 0.1.0\n\
         \x20 envelope hash  [traveler.json]   print the traveler hash\n\
         \x20 envelope level [traveler.json]   print the conformance level\n\
         \x20 envelope check [traveler.json]   JSON verdict {{accept, hash, level, bound}}\n\
         \x20 envelope verify <traveler.json> --directory <directory.json>\n\
         \x20                 (--root <hex> | --root-file <file>) [--at <UTC datetime>]\n\
         \x20                                  verify the buyer's authorship, the award and each\n\
         \x20                                  quote's seller signature against a signed directory\n\
         stdin is used when no file (or `-`) is given. A traveler is capped at 512 KiB.\n\
         Exit: 0 ok (check: a verdict was printed; verify: VERIFIED), 1 unreadable input,\n\
         \x20     2 refused / not verified / usage."
    );
}

/// `envelope verify`: print a JSON report and exit 0 only if the traveler is verified —
/// at least one valid buyer signature and, if it carries an award, a valid award. The
/// trust root is whatever the caller passes; this tool has none of its own.
fn verify(args: &[String]) -> ! {
    let mut traveler: Option<&str> = None;
    let (mut directory, mut root, mut root_file, mut at) = (None, None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let slot = match a.as_str() {
            "--directory" => &mut directory,
            "--root" => &mut root,
            "--root-file" => &mut root_file,
            "--at" => &mut at,
            other if other.starts_with("--") => usage_error(&format!("unknown option {}", printable(other))),
            other => {
                if traveler.replace(other).is_some() {
                    usage_error("more than one traveler file given");
                }
                continue;
            }
        };
        match it.next() {
            Some(v) if slot.is_none() => *slot = Some(v.as_str()),
            Some(_) => usage_error(&format!("{a} given more than once")),
            None => usage_error(&format!("{a} needs a value")),
        }
    }
    let (Some(traveler), Some(directory)) = (traveler, directory) else {
        usage_error("verify needs a traveler file and --directory");
    };
    let root_hex = match (root, root_file) {
        (Some(hex), None) => hex.to_string(),
        (None, Some(path)) => read_file(path, 16 * 1024).trim().to_string(),
        _ => usage_error("verify needs exactly one of --root and --root-file"),
    };
    let at_ms = match at {
        Some(text) => secure_job_envelope::datetime_millis(text)
            .unwrap_or_else(|| usage_error("--at must be a UTC datetime like 2026-09-16T12:00:00.000Z")),
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
    };
    let traveler_json = read_file(traveler, MAX_TRAVELER_JSON_BYTES);
    let dir_json = read_file(directory, MAX_DIRECTORY_JSON_BYTES);

    let report = sign::verify_report(&traveler_json, &dir_json, &root_hex, at_ms);
    let check = |c: &Check| {
        serde_json::json!({ "ok": c.ok, "kid": c.kid, "org_id": c.org_id, "reason": c.reason })
    };
    let out = serde_json::json!({
        "verified": report.verified(),
        "authorship": report.authorship.iter().map(check).collect::<Vec<_>>(),
        "award": report.award.as_ref().map(check),
        "quotes": report
            .quotes
            .iter()
            .map(|(id, c)| serde_json::json!({ "quote_id": id, "signature": c.as_ref().map(check) }))
            .collect::<Vec<_>>(),
    });
    println!("{out}");
    process::exit(if report.verified() { 0 } else { EXIT_REFUSED });
}

fn usage_error(msg: &str) -> ! {
    eprintln!("envelope: {msg}");
    usage(&mut io::stderr());
    process::exit(EXIT_REFUSED);
}

/// Read a whole file as UTF-8 text, at most `max` bytes (one more is read to detect
/// "too large"; a file past the cap or not UTF-8 is handed on as text no parser
/// accepts, so it is refused by the same code path as any other malformed input).
fn read_file(path: &str, max: usize) -> String {
    let mut buf = Vec::new();
    let read = File::open(path).and_then(|f| f.take(max as u64 + 1).read_to_end(&mut buf));
    if let Err(e) = read {
        eprintln!("{}: {}", printable(path), printable(&e.to_string()));
        process::exit(EXIT_IO);
    }
    if buf.len() > max {
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Print a refusal and exit non-zero. The message may quote document content (serde
/// names an unknown field, for instance), so it is made terminal-safe first.
fn refuse(msg: &str) -> ! {
    eprintln!("{}", printable(msg));
    process::exit(EXIT_REFUSED);
}

/// Escape characters that could rewrite the terminal when attacker-controlled text is
/// echoed: C0/C1 controls (ESC, CR, …), line/paragraph separators, and bidi overrides
/// and isolates. Without this a hostile file could, for example, emit a carriage return
/// and a fake "sha384:…" line of its own.
fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let risky = c.is_control()
            || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if risky {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

enum Input {
    Text(String),
    TooLarge,
    NotUtf8,
}

/// Read at most one byte past the document cap — never the whole stream. A traveler
/// larger than the cap is refused by the parser anyway; reading it all first let a
/// 512 MiB stdin cost 512 MiB of memory before the refusal.
fn read_input(path: Option<&str>) -> Input {
    let limit = (MAX_TRAVELER_JSON_BYTES as u64) + 1;
    let mut buf = Vec::new();
    let read = match path {
        Some("-") | None => io::stdin().lock().take(limit).read_to_end(&mut buf),
        Some(p) => File::open(p).and_then(|f| f.take(limit).read_to_end(&mut buf)),
    };
    if let Err(e) = read {
        eprintln!("{}: {}", printable(path.unwrap_or("stdin")), printable(&e.to_string()));
        process::exit(EXIT_IO);
    }
    if buf.len() > MAX_TRAVELER_JSON_BYTES {
        return Input::TooLarge;
    }
    match String::from_utf8(buf) {
        Ok(s) => Input::Text(s),
        Err(_) => Input::NotUtf8,
    }
}
