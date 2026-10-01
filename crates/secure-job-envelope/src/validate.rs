//! Structural validation, mirroring the TypeScript zod schema (schema.ts) field
//! for field. `parse_traveler` runs this after deserialization so the Rust core
//! accepts and rejects exactly the documents the reference implementation does —
//! same ceilings, same string bounds, same regexes, same strictness about unknown
//! keys and untrimmed strings. Without it the two implementations disagree on
//! which documents are well-formed, which breaks the "either implementation is
//! interchangeable" premise the whole project rests on.
//!
//! Two rules are subtle enough to call out:
//!   * String length limits count UTF-16 code units, because that is what
//!     JavaScript's `String.prototype.length` (and therefore zod `.max`) counts.
//!   * `.trim()` fields are validated, not transformed: a string with leading or
//!     trailing whitespace is *rejected* rather than silently trimmed, so the two
//!     implementations never hash a different byte string for the "same" document.
//!     Trimming semantics use the exact ECMAScript whitespace set (below).

use serde_json::Value;

use crate::{
    id_ok, iso_day_ok, rfc3339_millis, Award, AwardTerms, Error, Op, Org, Part, PriceLine, Pricing,
    Quote, QuoteException, ShipTo, Signature, Traveler,
};

const MAX_NAME: usize = 128;
const MAX_STRING: usize = 2000;
const QTY_MAX: i64 = 1_000_000;
const MONEY_MAX: i64 = 1_000_000_000_000; // 1e12

fn err(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// The ECMAScript `String.prototype.trim` whitespace set (WhiteSpace +
/// LineTerminator). It deliberately differs from Rust's `char::is_whitespace`:
/// it INCLUDES U+FEFF (ZWNBSP) and EXCLUDES U+0085 (NEL). Matching it exactly is
/// what makes "reject an untrimmed string" agree with the TypeScript side at the
/// boundary character.
fn is_js_ws(c: char) -> bool {
    matches!(c,
        '\u{0009}' | '\u{000A}' | '\u{000B}' | '\u{000C}' | '\u{000D}' | '\u{0020}'
        | '\u{00A0}' | '\u{1680}'
        | '\u{2000}'..='\u{200A}'
        | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}')
}

/// zod `.trim().min(1).max(max)`: reject empty, reject leading/trailing whitespace
/// (no silent trim), enforce the UTF-16 max.
fn trimmed(field: &str, s: &str, max: usize) -> Result<(), Error> {
    let Some(first) = s.chars().next() else {
        return Err(err(format!("{field} must not be empty")));
    };
    let last = s.chars().next_back().expect("non-empty");
    if is_js_ws(first) || is_js_ws(last) {
        return Err(err(format!("{field} must not have leading or trailing whitespace")));
    }
    let n = utf16_len(s);
    if n < 1 || n > max {
        return Err(err(format!("{field} length is out of range")));
    }
    Ok(())
}

/// zod `.min(min).max(max)` with no `.trim()`: length only (whitespace-only values
/// are allowed, matching the reference — only the trimmed fields reject them).
fn sized(field: &str, s: &str, min: usize, max: usize) -> Result<(), Error> {
    let n = utf16_len(s);
    if n < min || n > max {
        return Err(err(format!("{field} length is out of range")));
    }
    Ok(())
}

fn int_range(field: &str, v: i64, min: i64, max: i64) -> Result<(), Error> {
    if v < min || v > max {
        return Err(err(format!("{field} is out of range")));
    }
    Ok(())
}

fn money(field: &str, v: i64) -> Result<(), Error> {
    int_range(field, v, 0, MONEY_MAX)
}

/// org_id: /^[a-z][a-z0-9_]{1,63}$/ (total length 2..=64).
fn org_id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=64).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..].iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// HASH_RE: /^sha384:[0-9a-f]{96}$/.
fn hash_ok(s: &str) -> bool {
    s.len() == 7 + 96
        && s.starts_with("sha384:")
        && s[7..].bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn currency_ok(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|c| c.is_ascii_uppercase())
}

fn country_ok(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|c| c.is_ascii_uppercase())
}

fn lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn datetime_ok(s: &str) -> bool {
    rfc3339_millis(s).is_some()
}

/// zod `jsonBlob`: a JSON object whose compact serialization is <= 8 KiB.
fn json_blob(field: &str, v: &Value) -> Result<(), Error> {
    if !v.is_object() {
        return Err(err(format!("{field} must be a JSON object")));
    }
    let s = serde_json::to_string(v).map_err(|_| err(format!("{field} is not serializable")))?;
    if s.len() > 8192 {
        return Err(err(format!("{field} exceeds 8 KiB")));
    }
    Ok(())
}

fn thickness(v: f64) -> Result<(), Error> {
    // finite, 1e-4 <= x <= 1e6. The lower bound already implies zod's
    // `canonicalRange` (a non-integer of magnitude >= 1e-5), so every accepted
    // value also hashes in canonical fixed notation.
    if !v.is_finite() || v < 0.0001 || v > 1_000_000.0 {
        return Err(err("thickness_mm is out of range"));
    }
    Ok(())
}

fn org(o: &Org) -> Result<(), Error> {
    if let Some(id) = &o.org_id {
        if !org_id_ok(id) {
            return Err(err("org_id is not well-formed"));
        }
    }
    trimmed("name", &o.name, MAX_NAME)?;
    if let Some(c) = &o.city {
        trimmed("city", c, MAX_NAME)?;
    }
    if let Some(r) = &o.region {
        trimmed("region", r, MAX_NAME)?;
    }
    if let Some(c) = &o.contact {
        trimmed("contact", c, 200)?;
    }
    if let Some(certs) = &o.certs {
        if certs.len() > 16 {
            return Err(err("certs has more than 16 entries"));
        }
        for c in certs {
            sized("cert", c, 1, 64)?;
        }
    }
    Ok(())
}

fn part(p: &Part) -> Result<(), Error> {
    trimmed("part.family", &p.family, MAX_NAME)?;
    trimmed("part.part_number", &p.part_number, MAX_NAME)?;
    if let Some(d) = &p.description {
        sized("part.description", d, 1, MAX_STRING)?;
    }
    if let Some(dr) = &p.drawing_rev {
        sized("part.drawing_rev", dr, 1, 32)?;
    }
    trimmed("material.spec", &p.material.spec, MAX_NAME)?;
    if let Some(f) = &p.material.form {
        trimmed("material.form", f, MAX_NAME)?;
    }
    if let Some(th) = p.material.thickness_mm {
        thickness(th)?;
    }
    int_range("qty.target", p.qty.target, 1, QTY_MAX)?;
    if let Some(breaks) = &p.qty.breaks {
        if breaks.len() > 16 {
            return Err(err("qty.breaks has more than 16 entries"));
        }
        for b in breaks {
            int_range("qty.break", *b, 1, QTY_MAX)?;
        }
    }
    if let Some(procs) = &p.processes {
        if procs.len() > 32 {
            return Err(err("processes has more than 32 entries"));
        }
        for pr in procs {
            sized("process", pr, 1, 32)?;
        }
    }
    if let Some(f) = &p.finish {
        sized("part.finish", f, 1, MAX_STRING)?;
    }
    if let Some(t) = &p.tolerances {
        sized("part.tolerances", t, 1, MAX_STRING)?;
    }
    if let Some(n) = &p.notes {
        sized("part.notes", n, 1, MAX_STRING)?;
    }
    Ok(())
}

fn price_line(l: &PriceLine) -> Result<(), Error> {
    int_range("line.qty", l.qty, 1, QTY_MAX)?;
    money("line.unit", l.unit)
}

fn pricing(p: &Pricing) -> Result<(), Error> {
    if !currency_ok(&p.currency) {
        return Err(err("currency is not a 3-letter uppercase code"));
    }
    if let Some(nre) = p.nre {
        money("nre", nre)?;
    }
    if p.lines.is_empty() || p.lines.len() > 16 {
        return Err(err("pricing.lines must have between 1 and 16 entries"));
    }
    for l in &p.lines {
        price_line(l)?;
    }
    if let Some(f) = p.freight_estimate {
        money("freight_estimate", f)?;
    }
    Ok(())
}

fn exception(e: &QuoteException) -> Result<(), Error> {
    sized("exception.code", &e.code, 1, 64)?;
    if let Some(on) = &e.on {
        sized("exception.on", on, 1, 128)?;
    }
    sized("exception.proposal", &e.proposal, 1, MAX_STRING)?;
    if let Some(pd) = e.price_delta {
        int_range("price_delta", pd, -MONEY_MAX, MONEY_MAX)?;
    }
    Ok(())
}

fn signature(s: &Signature) -> Result<(), Error> {
    if s.alg != "ML-DSA-87" {
        return Err(err("signature alg must be ML-DSA-87"));
    }
    sized("sig.kid", &s.kid, 1, 64)?;
    if !lower_hex(&s.sig) || s.sig.len() > 20000 {
        return Err(err("sig must be lowercase hex within 20000 chars"));
    }
    Ok(())
}

fn quote(q: &Quote) -> Result<(), Error> {
    if !id_ok(&q.quote_id) {
        return Err(err("invalid quote_id"));
    }
    org(&q.seller)?;
    if !hash_ok(&q.traveler_hash_quoted) {
        return Err(err("traveler_hash_quoted is not a sha384 hash"));
    }
    let created = rfc3339_millis(&q.created_at).ok_or_else(|| err("quote created_at is not a canonical datetime"))?;
    let until = rfc3339_millis(&q.valid_until).ok_or_else(|| err("quote valid_until is not a canonical datetime"))?;
    if until <= created {
        return Err(err("valid_until must be after created_at"));
    }
    int_range("lead_time_days", q.lead_time_days, 0, 3650)?;
    pricing(&q.pricing)?;
    if let Some(a) = &q.assumptions {
        json_blob("assumptions", a)?;
    }
    if let Some(exs) = &q.exceptions {
        if exs.len() > 16 {
            return Err(err("exceptions has more than 16 entries"));
        }
        for e in exs {
            exception(e)?;
        }
    }
    if let Some(c) = &q.capacity {
        json_blob("capacity", c)?;
    }
    if let Some(s) = &q.sig {
        signature(s)?;
    }
    Ok(())
}

fn ship_to(s: &ShipTo) -> Result<(), Error> {
    trimmed("ship_to.name", &s.name, MAX_NAME)?;
    trimmed("ship_to.line1", &s.line1, 200)?;
    if let Some(l2) = &s.line2 {
        trimmed("ship_to.line2", l2, 200)?;
    }
    trimmed("ship_to.city", &s.city, MAX_NAME)?;
    trimmed("ship_to.region", &s.region, MAX_NAME)?;
    trimmed("ship_to.postal", &s.postal, 16)?;
    if !country_ok(&s.country) {
        return Err(err("country is not a 2-letter uppercase code"));
    }
    Ok(())
}

fn op(o: &Op) -> Result<(), Error> {
    int_range("op.seq", o.seq, 1, 1000)?;
    sized("op.code", &o.code, 1, 32)?;
    if let Some(n) = &o.notes {
        sized("op.notes", n, 1, MAX_STRING)?;
    }
    Ok(())
}

fn award_terms(t: &AwardTerms) -> Result<(), Error> {
    if let Some(g) = &t.governing_law {
        trimmed("governing_law", g, 128)?;
    }
    if let Some(w) = &t.warranty {
        sized("warranty", w, 1, MAX_STRING)?;
    }
    if let Some(p) = &t.payment_terms {
        trimmed("payment_terms", p, 128)?;
    }
    Ok(())
}

fn award(a: &Award) -> Result<(), Error> {
    if !id_ok(&a.quote_id) {
        return Err(err("invalid award.quote_id"));
    }
    if !datetime_ok(&a.awarded_at) {
        return Err(err("award.awarded_at is not a canonical datetime"));
    }
    int_range("award.qty", a.qty, 1, QTY_MAX)?;
    if let Some(t) = &a.terms {
        award_terms(t)?;
    }
    Ok(())
}

/// Validate a deserialized traveler against the full schema. `spec` is checked by
/// the caller (`parse_traveler`) before this runs.
pub fn traveler(t: &Traveler) -> Result<(), Error> {
    if !id_ok(&t.traveler_id) {
        return Err(err("invalid traveler_id"));
    }
    int_range("revision", t.revision, 1, 10_000)?;
    if !datetime_ok(&t.created_at) {
        return Err(err("created_at is not a canonical ISO-8601 UTC datetime"));
    }
    org(&t.buyer)?;
    part(&t.part)?;
    if let Some(nb) = &t.need_by {
        if !(iso_day_ok(nb) || datetime_ok(nb)) {
            return Err(err("need_by is not a valid ISO date or datetime"));
        }
    }
    if let Some(inc) = &t.incoterms {
        sized("incoterms", inc, 1, 64)?;
    }
    if let Some(st) = &t.ship_to {
        ship_to(st)?;
    }
    if let Some(ops) = &t.ops {
        if ops.len() > 64 {
            return Err(err("ops has more than 64 entries"));
        }
        for o in ops {
            op(o)?;
        }
    }
    if let Some(qs) = &t.quotes {
        if qs.len() > 64 {
            return Err(err("quotes has more than 64 entries"));
        }
        for q in qs {
            quote(q)?;
        }
    }
    if let Some(a) = &t.award {
        award(a)?;
    }
    if let Some(ab) = &t.as_built {
        json_blob("as_built", ab)?;
    }
    if let Some(sigs) = &t.signatures {
        if sigs.len() > 8 {
            return Err(err("signatures has more than 8 entries"));
        }
        for s in sigs {
            signature(s)?;
        }
    }
    // ITAR: an ITAR traveler cannot carry a quote from a non-ITAR seller.
    if t.itar.unwrap_or(false) {
        for q in t.quotes.as_deref().unwrap_or(&[]) {
            if q.seller.itar != Some(true) {
                return Err(err("ITAR traveler cannot carry a quote from a non-ITAR seller"));
            }
        }
    }
    Ok(())
}
