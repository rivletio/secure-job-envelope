//! Deserialization helpers that keep the Rust core accepting and rejecting exactly
//! the documents the TypeScript (zod) reference does. Two cross-implementation rules
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

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, Visitor};

/// 2^53 − 1, the largest integer exactly representable in an IEEE-754 double (and in
/// JavaScript). An integer-valued float is accepted only within ±this, matching the
/// canonical numeric range; a value's own field bound is enforced later by `validate`.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

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
