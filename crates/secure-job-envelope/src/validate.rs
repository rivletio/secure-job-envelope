//! Structural validation, mirroring the TypeScript zod schema (schema.ts) field
//! for field. `parse_traveler` runs this after deserialization so the Rust core
//! accepts and rejects exactly the documents the reference implementation does —
//! same ceilings, same string bounds, same regexes, same strictness about unknown
//! keys and untrimmed strings. Without it the two implementations disagree on
//! which documents are well-formed, which breaks the "either implementation is
//! interchangeable" premise the whole project rests on.
//!
//! Two rules are subtle enough to call out:
//!   * String length limits count Unicode code points (`str::chars().count()`),
//!     because zod v4's `.min`/`.max` on a string count code points, not UTF-16
//!     code units (e.g. `z.string().max(3)` accepts "😀😀😀" — three code points,
//!     six UTF-16 units). The cap on a free-form object is in neither unit: it is
//!     8 KiB of the object's canonical JSON, in UTF-8 bytes (see `json_blob`).
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

/// Code-point length, matching zod v4's string `.min`/`.max`. Used for every
/// user string field.
fn cp_len(s: &str) -> usize {
    s.chars().count()
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
/// (no silent trim), enforce the code-point max.
fn trimmed(field: &str, s: &str, max: usize) -> Result<(), Error> {
    let Some(first) = s.chars().next() else {
        return Err(err(format!("{field} must not be empty")));
    };
    let last = s.chars().next_back().expect("non-empty");
    if is_js_ws(first) || is_js_ws(last) {
        return Err(err(format!("{field} must not have leading or trailing whitespace")));
    }
    let n = cp_len(s);
    if n < 1 || n > max {
        return Err(err(format!("{field} length is out of range")));
    }
    Ok(())
}

/// zod `.min(min).max(max)` with no `.trim()`: length only (whitespace-only values
/// are allowed, matching the reference — only the trimmed fields reject them).
fn sized(field: &str, s: &str, min: usize, max: usize) -> Result<(), Error> {
    let n = cp_len(s);
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
pub(crate) fn org_id_ok(s: &str) -> bool {
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

/// True iff every character is ECMAScript whitespace (so JS `s.trim()` is empty).
/// Used by the level logic, which must agree with the TypeScript `x.trim().length > 0`
/// — Rust's own `str::trim` strips U+0085 and keeps U+FEFF, the opposite of JS.
pub(crate) fn js_blank(s: &str) -> bool {
    s.chars().all(is_js_ws)
}

/// A member named `__proto__`, at any depth. The name is refused everywhere in a
/// traveler: in typed positions `deny_unknown_fields` already rejects it, and inside
/// a free-form blob the TypeScript reference cannot represent it faithfully (zod's
/// record silently drops an own `__proto__` key), so the two implementations would
/// otherwise canonicalize — and therefore sign and verify — different bytes for the
/// same wire document. Refusing the name on both sides removes the fork.
fn has_proto_member(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.iter().any(|(k, child)| k == "__proto__" || has_proto_member(child)),
        Value::Array(items) => items.iter().any(has_proto_member),
        _ => false,
    }
}

/// True iff `raw` (the document as written) is an OBJECT at every position where the
/// typed document is one. serde's derived `Deserialize` accepts a struct written as a
/// positional JSON array (`"material": ["6061-T6"]`, or the whole traveler as one
/// array); zod does not. Beyond the accept/reject split, code that reads the raw JSON
/// by key (signature verification) would then see a different document from the typed
/// one. `typed` is the parsed traveler re-serialized, where every struct is an object.
pub(crate) fn no_positional_structs(raw: &Value, typed: &Value) -> bool {
    match (raw, typed) {
        (Value::Object(r), Value::Object(t)) => t
            .iter()
            .all(|(k, tv)| r.get(k).map(|rv| no_positional_structs(rv, tv)).unwrap_or(true)),
        (_, Value::Object(_)) => false,
        (Value::Array(r), Value::Array(t)) => {
            r.len() == t.len() && r.iter().zip(t).all(|(a, b)| no_positional_structs(a, b))
        }
        (_, Value::Array(_)) => false,
        _ => true,
    }
}

/// The cap on a free-form object, in bytes of its canonical JSON (UTF-8).
pub const MAX_BLOB_BYTES: usize = 8192;

/// A free-form object (`as_built`, a quote's `assumptions` and `capacity`): anything a
/// writer likes, on two conditions every implementation can check the same way.
///
///   1. It has a canonical form: every number in it is a canonical number. A quote's
///      blobs are inside the quote's content hash and signature, so a number with no
///      canonical form made a quote that parsed but could never be hashed.
///   2. That canonical form is at most 8 KiB of UTF-8.
///
/// The size used to be measured on each implementation's own re-serialization
/// (`serde_json::to_string` here, `JSON.stringify` in TypeScript), and the two write
/// numbers at different lengths (`1e15` is 18 characters in one and 16 in the other),
/// so a blob of a few hundred numbers was accepted by one side and refused by the
/// other. The canonical form is the one serialization both sides already have to
/// produce byte for byte.
fn json_blob(field: &str, v: &Value) -> Result<(), Error> {
    if !v.is_object() {
        return Err(err(format!("{field} must be a JSON object")));
    }
    if has_proto_member(v) {
        return Err(err(format!("{field} contains a member named __proto__")));
    }
    let canonical = crate::canonical_json(v).map_err(|e| {
        let why = match e {
            Error::Invalid(why) => why,
            other => other.to_string(),
        };
        err(format!("{field} has no canonical form: {why}"))
    })?;
    if canonical.len() > MAX_BLOB_BYTES {
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
    for (i, l) in p.lines.iter().enumerate() {
        price_line(l)?;
        // One price per quantity: two lines for the same qty would leave the unit
        // price ambiguous under an award (the first would silently win).
        if p.lines[..i].iter().any(|prev| prev.qty == l.qty) {
            return Err(err("pricing.lines has more than one line for the same qty"));
        }
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

pub(crate) fn quote(q: &Quote) -> Result<(), Error> {
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
    if let Some(h) = &a.quote_hash {
        if !hash_ok(h) {
            return Err(err("award.quote_hash is not a sha384 hash"));
        }
    }
    if !datetime_ok(&a.awarded_at) {
        return Err(err("award.awarded_at is not a canonical datetime"));
    }
    int_range("award.qty", a.qty, 1, QTY_MAX)?;
    if let Some(t) = &a.terms {
        award_terms(t)?;
    }
    // The award's own signature object is validated like every other signature
    // (alg, kid bounds, lowercase hex, length) — it was the one signature site the
    // validator skipped, so a garbage `award.sig` parsed here and not in TypeScript.
    if let Some(s) = &a.sig {
        signature(s)?;
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
        for (i, o) in ops.iter().enumerate() {
            op(o)?;
            if ops[..i].iter().any(|prev| prev.seq == o.seq) {
                return Err(err("ops has more than one entry with the same seq"));
            }
        }
    }
    if let Some(qs) = &t.quotes {
        if qs.len() > 64 {
            return Err(err("quotes has more than 64 entries"));
        }
        for (i, q) in qs.iter().enumerate() {
            quote(q)?;
            // quote_id identifies a quote within a traveler; an award names a quote by
            // id. Two quotes sharing an id let an award bind a different quote from the
            // one a reader is shown (the first match by id), so the id must be unique.
            if qs[..i].iter().any(|prev| prev.quote_id == q.quote_id) {
                return Err(err("quotes has more than one quote with the same quote_id"));
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_limits_count_code_points_like_zod_v4() {
        // zod v4's string `.min`/`.max` count code points, not UTF-16 code units.
        // "😀" (U+1F600) is one code point but two UTF-16 units, so a field capped at
        // MAX_NAME=128 must accept 128 emoji and reject 129 — matching the reference,
        // which previously disagreed because this core counted UTF-16 units.
        let n128: String = "😀".repeat(128);
        let n129: String = "😀".repeat(129);
        assert_eq!(cp_len(&n128), 128);
        assert_eq!(n128.encode_utf16().count(), 256);
        assert!(trimmed("family", &n128, MAX_NAME).is_ok());
        assert!(trimmed("family", &n129, MAX_NAME).is_err());
        // The no-trim `sized` fields count code points too.
        assert!(sized("code", &"😀".repeat(32), 1, 32).is_ok());
        assert!(sized("code", &"😀".repeat(33), 1, 32).is_err());
    }

    #[test]
    fn a_blob_is_measured_on_its_canonical_form_in_bytes() {
        use serde_json::json;
        // The cap is 8,192 bytes of the canonical JSON. `{"k":"…"}` costs 8 bytes of
        // framing, so 8,184 ASCII characters fit and 8,185 do not.
        assert!(json_blob("as_built", &json!({ "k": "x".repeat(8184) })).is_ok());
        let over = json_blob("as_built", &json!({ "k": "x".repeat(8185) })).unwrap_err();
        assert_eq!(over.to_string(), "as_built exceeds 8 KiB");
        // Bytes, not characters or UTF-16 units: U+6F22 is one unit and three bytes.
        assert!(json_blob("as_built", &json!({ "k": "\u{6f22}".repeat(2728) })).is_ok());
        assert!(json_blob("as_built", &json!({ "k": "\u{6f22}".repeat(2729) })).is_err());
        // The canonical form, not this library's own rendering of a number. Written as
        // `1.0`, 4,092 ones are 16,375 characters here and 8,191 canonical bytes: accepted.
        let list = |item: &str, n: usize| -> Value {
            serde_json::from_str(&format!("{{\"k\":[{}]}}", vec![item; n].join(","))).unwrap()
        };
        let ones = list("1.0", 4092);
        assert!(serde_json::to_string(&ones).unwrap().len() > 2 * MAX_BLOB_BYTES - 16);
        assert_eq!(crate::canonical_json(&ones).unwrap().len(), 8191);
        assert!(json_blob("as_built", &ones).is_ok());
        // `1e15` is sixteen canonical digits (this library would write eighteen
        // characters): 481 of them fit in 8,184 bytes, 482 do not.
        assert_eq!(crate::canonical_json(&list("1e15", 481)).unwrap().len(), 8184);
        assert!(json_blob("as_built", &list("1e15", 481)).is_ok());
        assert!(json_blob("as_built", &list("1e15", 482)).is_err());
        // A number with no canonical form has no size to measure: the blob is refused,
        // and for that reason.
        for (text, why) in [("1e20", "exceeds 2^53-1"), ("1e-7", "below 1e-5"), ("9007199254740993", "exceeds 2^53-1")] {
            let v: Value = serde_json::from_str(&format!("{{\"k\":{text}}}")).unwrap();
            let refusal = json_blob("assumptions", &v).unwrap_err().to_string();
            assert!(refusal.starts_with("assumptions has no canonical form: "), "{refusal}");
            assert!(refusal.contains(why), "{text}: {refusal}");
        }
    }

    #[test]
    fn blank_follows_ecmascript_whitespace_not_rust_trim() {
        // The two sets differ at exactly these characters. JS `"\u{85}".trim()` is
        // non-empty (NEL is not ECMAScript whitespace); Rust `str::trim` strips it.
        // JS strips U+FEFF; Rust keeps it. `js_blank` must side with JS on both.
        assert!(!js_blank("\u{85}"));
        assert!("\u{85}".trim().is_empty(), "the Rust behaviour this replaces");
        assert!(js_blank("\u{FEFF}"));
        assert!(!"\u{FEFF}".trim().is_empty(), "the Rust behaviour this replaces");
        assert!(js_blank("") && js_blank(" \t\u{A0}\u{2028}"));
        assert!(!js_blank(" x "));
    }

    #[test]
    fn positional_structs_and_proto_members_are_detected() {
        let v = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        // typed side: what a struct re-serializes to (always an object).
        let typed = v(r#"{"material":{"spec":"M"},"breaks":[1,2],"blob":{"a":[{"b":1}]}}"#);
        assert!(no_positional_structs(&typed, &typed));
        // a struct written positionally, at any depth, is refused …
        assert!(!no_positional_structs(&v(r#"{"material":["M"],"breaks":[1,2]}"#), &typed));
        assert!(!no_positional_structs(&v(r#"[{"spec":"M"},[1,2]]"#), &typed));
        // … an absent optional is fine, and a real array stays an array.
        assert!(no_positional_structs(&v(r#"{"breaks":[1,2]}"#), &typed));
        assert!(!no_positional_structs(&v(r#"{"breaks":[1]}"#), &typed));

        assert!(has_proto_member(&v(r#"{"__proto__":1}"#)));
        assert!(has_proto_member(&v(r#"{"a":[{"b":{"__proto__":null}}]}"#)));
        assert!(!has_proto_member(&v(r#"{"proto":1,"a":["__proto__"]}"#)), "only a member NAME counts");
    }
}
