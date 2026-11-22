//! Deserialization helpers that keep the Rust core accepting and rejecting exactly
//! the documents the TypeScript (zod) reference does. Three cross-implementation rules
//! the default serde behavior gets wrong:
//!
//!   * **Integer-valued floats.** zod `z.number().int()` accepts `250.0` (in JS
//!     `250.0 === 250`, and the canonicalizer renders it `250` — see docs/SPEC.md
//!     §Canonical JSON), but serde refuses a float token for an `i64` field at parse.
//!     `i64_lenient` / `opt_i64` / `opt_vec_i64` accept an integer-valued float (`N.0`)
//!     for an integer field — rejecting a fractional or out-of-range value — so `250.0`
//!     parses here too and hashes identically to `250`. The field's own numeric bound
//!     is still enforced afterwards by `validate.rs`.
//!
//!   * **Explicit `null` on an optional-but-not-nullable field.** serde `Option<T>`
//!     maps JSON `null` to `None` and accepts it; zod `.optional()` (without
//!     `.nullable()`) rejects `null`, and the published JSON Schema types these fields
//!     without `null`. `present_some` is applied to every optional field that is NOT
//!     one of the five explicitly-nullable fields (need_by, incoterms, ship_to, award,
//!     as_built), so an explicit `null` there is refused. It only ever runs when the
//!     key is present (an absent field still deserializes to `None` via
//!     `#[serde(default)]`), so a `None` inside it means the value was literally `null`.
//!
//!   * **A repeated member name inside a free-form blob.** A typed struct refuses a
//!     duplicated field, but `serde_json::Value` — what `assumptions`, `capacity` and
//!     `as_built` deserialize into — silently keeps the last. The TypeScript reference
//!     refuses a repeated member name anywhere in the wire text, so the blobs are read
//!     through `Blob`, which refuses one at any depth. Without this a document was
//!     accepted or refused depending on which implementation read it, and (worse) a
//!     shadowed value was never examined by a last-wins parser at all.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::MAX_SAFE_INTEGER;

struct LenientI64;

impl<'de> Visitor<'de> for LenientI64 {
    type Value = i64;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an integer, optionally written as an integer-valued float (e.g. 250.0)")
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> {
        Ok(v)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> {
        i64::try_from(v).map_err(|_| E::custom("integer is out of i64 range"))
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<i64, E> {
        i64::try_from(v).map_err(|_| E::custom("integer is out of i64 range"))
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<i64, E> {
        i64::try_from(v).map_err(|_| E::custom("integer is out of i64 range"))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<i64, E> {
        // Accept an integer-valued float (N.0) iff it is finite, integral, and within
        // the safe-integer range; reject a fractional or out-of-range float. Mirrors
        // the canonicalizer (10.0 renders as 10) and zod `.int()`.
        if v.is_finite() && v.fract() == 0.0 && v.abs() <= MAX_SAFE_INTEGER {
            Ok(v as i64)
        } else {
            Err(E::custom("expected an integer value"))
        }
    }
}

/// Newtype carrying the lenient-integer parse, so serde's own `Option` / `Vec`
/// deserialization composes on top of it (used by `opt_i64` / `opt_vec_i64`).
struct Int(i64);

impl<'de> Deserialize<'de> for Int {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LenientI64).map(Int)
    }
}

/// A required integer field: accepts an integer or an integer-valued float.
pub(crate) fn i64_lenient<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Int::deserialize(d).map(|w| w.0)
}

/// An optional integer field (present → not null): rejects `null`, accepts an integer
/// or an integer-valued float. Only called when the key is present.
pub(crate) fn opt_i64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    match Option::<Int>::deserialize(d)? {
        Some(w) => Ok(Some(w.0)),
        None => Err(de::Error::custom("field must not be null")),
    }
}

/// An optional integer array (present → not null): rejects `null`, accepts integers or
/// integer-valued floats as elements.
pub(crate) fn opt_vec_i64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<i64>>, D::Error> {
    match Option::<Vec<Int>>::deserialize(d)? {
        Some(v) => Ok(Some(v.into_iter().map(|w| w.0).collect())),
        None => Err(de::Error::custom("field must not be null")),
    }
}

/// A present optional field that is NOT nullable: refuse an explicit `null`, matching
/// zod `.optional()` and the published JSON Schema. `None` here means the value was
/// literally `null` (an absent key is handled by `#[serde(default)]`, which does not
/// call this).
pub(crate) fn present_some<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    match Option::<T>::deserialize(d)? {
        Some(v) => Ok(Some(v)),
        None => Err(de::Error::custom("field must not be null")),
    }
}

/// A `serde_json::Value` that refuses a repeated member name at any depth. Otherwise
/// identical to `Value`'s own deserialization (same number mapping; serde_json's
/// recursion limit still applies).
struct Blob(Value);

struct BlobVisitor;

impl<'de> Visitor<'de> for BlobVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value with no repeated member names")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(BlobVisitor)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Blob(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if out.contains_key(&name) {
                return Err(de::Error::custom("duplicate member name in a free-form object"));
            }
            let Blob(v) = map.next_value()?;
            out.insert(name, v);
        }
        Ok(Value::Object(out))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(BlobVisitor).map(Blob)
    }
}

/// Parse JSON text into a `Value`, refusing a repeated member name at any depth (plain
/// `Value` deserialization keeps the last). serde_json itself already refuses a
/// byte-order mark, nesting past its recursion limit, and anything after the value.
pub(crate) fn strict_value(text: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str::<Blob>(text).map(|b| b.0)
}

/// A present, non-nullable free-form blob (`quote.assumptions`, `quote.capacity`):
/// refuses an explicit `null` like `present_some`, and a repeated member name.
pub(crate) fn blob_present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    match Option::<Blob>::deserialize(d)? {
        Some(Blob(v)) => Ok(Some(v)),
        None => Err(de::Error::custom("field must not be null")),
    }
}

/// A nullable free-form blob (`traveler.as_built`): an explicit `null` is absent; a
/// repeated member name is refused.
pub(crate) fn blob_nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Ok(Option::<Blob>::deserialize(d)?.map(|b| b.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    struct Holder {
        #[serde(default, deserialize_with = "blob_present")]
        present: Option<Value>,
        #[serde(default, deserialize_with = "blob_nullable")]
        nullable: Option<Value>,
    }

    fn parse(json: &str) -> Result<Holder, String> {
        serde_json::from_str::<Holder>(json).map_err(|e| e.to_string())
    }

    #[test]
    fn blob_refuses_a_repeated_member_name_at_any_depth() {
        for json in [
            r#"{"present":{"lot":"A","lot":"B"}}"#,
            r#"{"nullable":{"lot":"A","lot":"B"}}"#,
            // nested: object inside an array inside an object
            r#"{"present":{"runs":[{"n":1},{"n":2,"n":3}]}}"#,
            r#"{"nullable":{"a":{"b":{"c":1,"c":1}}}}"#,
            // the empty name is a name
            r#"{"present":{"":1,"":2}}"#,
        ] {
            let err = parse(json).expect_err(json);
            assert!(err.contains("duplicate member name in a free-form object"), "{json}: {err}");
        }
    }

    #[test]
    fn blob_compares_member_names_after_unescaping() {
        // "\u006cot" spells "lot": the two names are equal once unescaped, so the second
        // repeats the first however each was written.
        let escaped = r#"{"present":{"lot":"A","\u006cot":"B"}}"#;
        // This case used to sit in the list above and had lost its escape — its text had
        // become a second copy of the plain "lot"/"lot" case — and it went on passing. So,
        // before the refusal: the text does carry an escape, and the names are the same
        // only AFTER unescaping (a reader that keeps the last of a repeated name is left
        // with the one member, "lot").
        assert!(escaped.contains('\\'), "the fixture has lost its escape");
        let last_wins: Value = serde_json::from_str(escaped).unwrap();
        assert_eq!(last_wins["present"], serde_json::json!({ "lot": "B" }));
        let err = parse(escaped).expect_err(escaped);
        assert!(err.contains("duplicate member name in a free-form object"), "{escaped}: {err}");
        // Control: an escape does not make a name a repeat. "\u006dot" spells "mot".
        let other = parse(r#"{"present":{"lot":"A","\u006dot":"B"}}"#).unwrap().present.unwrap();
        assert_eq!(other, serde_json::json!({ "lot": "A", "mot": "B" }));
    }

    #[test]
    fn blob_keeps_everything_a_plain_value_parse_keeps() {
        // Same member name in sibling objects or at different depths is not a repeat.
        let json = r#"{"present":{"a":{"a":{"a":1}},"list":[{"k":1},{"k":1}],"n":null,
            "i":-7,"u":18446744073709551615,"f":0.5,"neg0":-0,"e":1e3,"s":"x","t":true}}"#;
        let got = parse(json).unwrap().present.unwrap();
        // Byte-for-byte what serde_json::Value itself would have produced — the blob
        // reader changes what is REFUSED, never what an accepted blob contains.
        let plain: Value = serde_json::from_str(json).unwrap();
        assert_eq!(got, plain["present"]);
        assert_eq!(got["u"], serde_json::json!(18446744073709551615u64));
        assert!(got["neg0"].is_f64(), "-0 stays a float, as in Value");
    }

    #[test]
    fn blob_null_rules_are_unchanged() {
        // non-nullable blob: explicit null refused; absent is None
        assert!(parse(r#"{"present":null}"#).unwrap_err().contains("must not be null"));
        assert!(parse("{}").unwrap().present.is_none());
        // nullable blob: explicit null and absent are both None
        assert!(parse(r#"{"nullable":null}"#).unwrap().nullable.is_none());
        assert!(parse("{}").unwrap().nullable.is_none());
        // a non-object is still read (the validator, not the reader, requires an object)
        assert_eq!(parse(r#"{"nullable":[1,2]}"#).unwrap().nullable.unwrap(), serde_json::json!([1, 2]));
    }

    #[test]
    fn blob_still_refuses_what_the_json_parser_refuses() {
        // out-of-range number, even when a later duplicate would have shadowed it: refused
        // as a number, at the number (column 21 is the end of `1e309`), so before the
        // repeated name after it is reached — and the same with no repeat to reach.
        for json in [r#"{"present":{"x":1e309,"x":1}}"#, r#"{"present":{"x":1e309}}"#] {
            assert_eq!(parse(json).expect_err(json), "number out of range at line 1 column 21", "{json}");
        }
        // control: the number is the one thing wrong — the largest power of ten a double
        // holds is read
        let largest = parse(r#"{"present":{"x":1e308}}"#).unwrap().present.unwrap();
        assert_eq!(largest, serde_json::json!({ "x": 1e308 }));
        // serde_json's recursion limit still applies inside a blob
        let deep = format!(r#"{{"present":{}{}}}"#, "[".repeat(200), "]".repeat(200));
        assert!(parse(&deep).unwrap_err().contains("recursion limit"));
    }
}
