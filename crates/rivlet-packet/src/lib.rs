//! Rivlet Packet 0.0.1
//!
//! Content-addressed envelope for one part family moving between two manufacturers.
//! Quotes bind to `sha384:` + hex of canonical JSON of the quoteable body.
//!
//! The hash is integrity of the buyer-authored body, not a signature. 0.0.1 does
//! not authenticate parties, implement ITAR/EAR access control, or form a contract.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha384};

pub const SPEC: &str = "rivlet-packet/0.0.1";
pub const MEDIA_TYPE: &str = "application/vnd.rivlet.packet+json";
pub const GOLDEN_HASH: &str =
    "sha384:6892aec9ee18e89bd189a646808a4920ca0972a41225d8f8556d796687a14e6213182ea8a657c694023856a712773fac";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not quoteable: {0}")]
    Draft(String),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub itar: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Material {
    pub spec: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thickness_mm: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Qty {
    pub target: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breaks: Option<Vec<i64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Part {
    pub family: String,
    pub part_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawing_rev: Option<String>,
    pub material: Material,
    pub qty: Qty,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerances: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceLine {
    pub qty: i64,
    pub unit: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pricing {
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nre: Option<f64>,
    pub lines: Vec<PriceLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freight_estimate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tax_excluded: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteException {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<String>,
    pub proposal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_delta: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    pub quote_id: String,
    pub seller: Org,
    pub packet_hash_quoted: String,
    pub created_at: String,
    pub valid_until: String,
    pub lead_time_days: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub need_by_feasible: Option<bool>,
    pub pricing: Pricing,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assumptions: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<QuoteException>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShipTo {
    pub name: String,
    pub line1: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line2: Option<String>,
    pub city: String,
    pub region: String,
    pub postal: String,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Op {
    pub seq: i64,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Award {
    pub quote_id: String,
    pub awarded_at: String,
    pub qty: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub spec: String,
    pub packet_id: String,
    pub revision: i64,
    pub created_at: String,
    pub buyer: Org,
    pub part: Part,
    #[serde(default)]
    pub need_by: Option<String>,
    #[serde(default)]
    pub incoterms: Option<String>,
    #[serde(default)]
    pub itar: Option<bool>,
    #[serde(default)]
    pub ship_to: Option<ShipTo>,
    #[serde(default)]
    pub ops: Option<Vec<Op>>,
    #[serde(default)]
    pub quotes: Option<Vec<Quote>>,
    #[serde(default)]
    pub award: Option<Award>,
    #[serde(default)]
    pub as_built: Option<Value>,
}

/// Buyer-authored body. Quotes bind to the hash of this object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quoteable {
    pub spec: String,
    pub packet_id: String,
    pub revision: i64,
    pub created_at: String,
    pub buyer: Org,
    pub part: Part,
    pub need_by: Option<String>,
    pub incoterms: Option<String>,
    pub itar: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Level {
    pub n: u8,
    pub code: &'static str,
    pub name: &'static str,
}

pub fn parse_packet(json: &str) -> Result<Packet, Error> {
    if json.len() > 512 * 1024 {
        return Err(Error::Invalid("packet json exceeds 512 KiB".into()));
    }
    let packet: Packet = serde_json::from_str(json)?;
    if packet.spec != SPEC {
        return Err(Error::Invalid("unsupported spec".into()));
    }
    if !id_ok(&packet.packet_id) {
        return Err(Error::Invalid("invalid packet_id".into()));
    }
    if packet.itar.unwrap_or(false) {
        for q in packet.quotes.as_deref().unwrap_or(&[]) {
            if q.seller.itar != Some(true) {
                return Err(Error::Invalid(
                    "ITAR packet quoted by a seller without itar: true".into(),
                ));
            }
        }
    }
    Ok(packet)
}

fn id_ok(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() < 10 || bytes.len() > 28 {
        return false;
    }
    let Some((pfx, rest)) = id.split_once('_') else {
        return false;
    };
    pfx.len() == 3
        && pfx.bytes().all(|b| b.is_ascii_lowercase())
        && (6..=24).contains(&rest.len())
        && rest.bytes().all(|b| b.is_ascii_alphanumeric() && !b.is_ascii_uppercase())
}

pub fn quoteable_from(packet: &Packet) -> Quoteable {
    Quoteable {
        spec: packet.spec.clone(),
        packet_id: packet.packet_id.clone(),
        revision: packet.revision,
        created_at: packet.created_at.clone(),
        buyer: packet.buyer.clone(),
        part: packet.part.clone(),
        need_by: packet.need_by.clone(),
        incoterms: packet.incoterms.clone(),
        itar: packet.itar.unwrap_or(false),
    }
}

/// RFC 8785-ish: sorted keys, compact JSON, JS NumberToJSON for numbers.
/// Integer-valued floats emit without a trailing `.0` so Rust matches `JSON.stringify`.
pub fn canonical_json(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_canonical(&mut out, value)?;
    Ok(out)
}

fn write_canonical(out: &mut String, value: &Value) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n)?,
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).expect("string json"));
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(*k).expect("key json"));
                out.push(':');
                write_canonical(out, &map[*k])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Numbers must land byte-identical across implementations, so 0.0.1 only
/// admits values whose shortest JSON rendering is plain fixed notation.
/// JS `Number::toString` and Rust's ryu disagree on exponent formatting
/// (`1e+21` vs `1e21`), so any value that would render with an exponent is
/// refused rather than hashed ambiguously. The TypeScript implementation
/// enforces the same rule.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0; // 2^53 - 1

fn write_number(out: &mut String, n: &serde_json::Number) -> Result<(), Error> {
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
            return Err(Error::Invalid(
                "integer exceeds 2^53-1 and is not canonical in rivlet-packet/0.0.1".into(),
            ));
        }
        out.push_str(&i.to_string());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER as u64 {
            return Err(Error::Invalid(
                "integer exceeds 2^53-1 and is not canonical in rivlet-packet/0.0.1".into(),
            ));
        }
        out.push_str(&u.to_string());
        return Ok(());
    }
    let f = n
        .as_f64()
        .filter(|f| f.is_finite())
        .ok_or_else(|| Error::Invalid("non-finite number is not canonical".into()))?;
    if f == 0.0 {
        out.push('0');
        return Ok(());
    }
    if f.abs() > MAX_SAFE_INTEGER {
        return Err(Error::Invalid(
            "number exceeds 2^53-1 and is not canonical in rivlet-packet/0.0.1".into(),
        ));
    }
    if f.fract() == 0.0 {
        out.push_str(&format!("{:.0}", f));
        return Ok(());
    }
    if f.abs() < 1e-5 {
        return Err(Error::Invalid(
            "non-integer number below 1e-5 is outside the canonical fixed-notation range of rivlet-packet/0.0.1".into(),
        ));
    }
    let rendered = serde_json::to_string(&f).expect("finite f64");
    if rendered.contains('e') || rendered.contains('E') {
        return Err(Error::Invalid(
            "number outside the canonical fixed-notation range of rivlet-packet/0.0.1".into(),
        ));
    }
    out.push_str(&rendered);
    Ok(())
}

pub fn hash_quoteable(body: &Quoteable) -> Result<String, Error> {
    let value = serde_json::to_value(body).expect("quoteable value");
    let bytes = canonical_json(&value)?;
    let digest = Sha384::digest(bytes.as_bytes());
    Ok(format!("sha384:{}", hex::encode(digest)))
}

pub fn packet_hash(packet: &Packet) -> Result<String, Error> {
    hash_quoteable(&quoteable_from(packet))
}

pub fn is_quoteable(packet: &Packet) -> bool {
    !packet.buyer.name.trim().is_empty()
        && !packet.part.family.trim().is_empty()
        && !packet.part.part_number.trim().is_empty()
        && !packet.part.material.spec.trim().is_empty()
        && packet.part.qty.target >= 1
}

/// A packet whose quoteable body cannot hash (out-of-range numbers) can have
/// no bound quotes: binding is defined by the hash.
pub fn bound_quotes(packet: &Packet) -> Vec<&Quote> {
    let Ok(hash) = packet_hash(packet) else {
        return Vec::new();
    };
    packet
        .quotes
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|q| q.packet_hash_quoted == hash && quote_ok(q, packet))
        .collect()
}

fn money_ok(n: f64) -> bool {
    n.is_finite() && n >= 0.0 && n <= 1e12
}

fn quote_ok(q: &Quote, packet: &Packet) -> bool {
    let currency = q.pricing.currency.as_bytes();
    let hash_ok = q.packet_hash_quoted.starts_with("sha384:")
        && q.packet_hash_quoted.len() == "sha384:".len() + 96
        && q.packet_hash_quoted[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    let itar_ok = !packet.itar.unwrap_or(false) || q.seller.itar == Some(true);
    !q.quote_id.is_empty()
        && id_ok(&q.quote_id)
        && !q.seller.name.is_empty()
        && q.lead_time_days >= 0
        && currency.len() == 3
        && currency.iter().all(|b| b.is_ascii_uppercase())
        && !q.pricing.lines.is_empty()
        && q.pricing.lines.iter().all(|l| l.qty >= 1 && money_ok(l.unit))
        && q.pricing.nre.map(money_ok).unwrap_or(true)
        && q.pricing.freight_estimate.map(money_ok).unwrap_or(true)
        && hash_ok
        && itar_ok
}

pub fn quote_expired(q: &Quote, now_ms: i64) -> bool {
    match chrono_millis(&q.valid_until) {
        Some(until) => now_ms > until,
        None => true,
    }
}

fn chrono_millis(iso: &str) -> Option<i64> {
    rfc3339_millis(iso)
}

fn rfc3339_millis(iso: &str) -> Option<i64> {
    // 2026-09-30T00:00:00.000Z or 2026-09-30T00:00:00Z
    let body = iso.strip_suffix('Z')?;
    let (date, time) = body.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let (hms, frac) = match time.split_once('.') {
        Some((hms, f)) => (hms, f),
        None => (time, "0"),
    };
    let mut t = hms.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let min: i64 = t.next()?.parse().ok()?;
    let s: i64 = t.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let mut ms: i64 = 0;
    if !frac.is_empty() {
        let padded = format!("{:0<3}", frac.chars().take(3).collect::<String>());
        ms = padded.parse().ok()?;
    }
    // Unix ms via days from 1970-01-01 UTC, civil date algorithm (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86_400_000 + h * 3_600_000 + min * 60_000 + s * 1_000 + ms)
}

pub fn level(packet: &Packet) -> Level {
    if !is_quoteable(packet) {
        return Level {
            n: 0,
            code: "D",
            name: "Draft",
        };
    }
    let bound = bound_quotes(packet);
    if bound.is_empty() {
        return Level {
            n: 0,
            code: "L0",
            name: "Quoteable",
        };
    }
    let award_ok = packet
        .award
        .as_ref()
        .map(|a| bound.iter().any(|q| q.quote_id == a.quote_id))
        .unwrap_or(false);
    let ops_ok = packet
        .ops
        .as_ref()
        .map(|o| !o.is_empty())
        .unwrap_or(false);
    let ship_ok = packet
        .ship_to
        .as_ref()
        .map(|s| !s.name.is_empty() && !s.line1.is_empty() && !s.city.is_empty())
        .unwrap_or(false);
    if !award_ok || !ops_ok || !ship_ok {
        return Level {
            n: 1,
            code: "L1",
            name: "Awardable",
        };
    }
    if packet
        .as_built
        .as_ref()
        .and_then(|v| v.as_object())
        .map(|m| !m.is_empty())
        .unwrap_or(false)
    {
        return Level {
            n: 3,
            code: "L3",
            name: "As-built",
        };
    }
    Level {
        n: 2,
        code: "L2",
        name: "Executable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_hash_matches_ts() {
        let body: Quoteable = serde_json::from_str(include_str!("../tests/golden.json")).unwrap();
        assert_eq!(hash_quoteable(&body).unwrap(), GOLDEN_HASH);
    }

    #[test]
    fn canonical_sorts_keys() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn integer_valued_float_matches_json_stringify() {
        let ten = serde_json::json!({"t": 10.0f64});
        assert_eq!(canonical_json(&ten).unwrap(), r#"{"t":10}"#);
        let n = serde_json::json!({"t": 9.53f64});
        assert_eq!(canonical_json(&n).unwrap(), r#"{"t":9.53}"#);
        let z = serde_json::json!({"t": -0.0f64});
        assert_eq!(canonical_json(&z).unwrap(), r#"{"t":0}"#);
    }

    #[test]
    fn canonical_refuses_exponential_notation() {
        let big = serde_json::json!({"t": 1e21f64});
        assert!(canonical_json(&big).is_err());
        let tiny = serde_json::json!({"t": 1e-7f64});
        assert!(canonical_json(&tiny).is_err());
        let below_range = serde_json::json!({"t": 0.000001f64});
        assert!(canonical_json(&below_range).is_err());
        let big_int = serde_json::json!({"t": 9_007_199_254_740_992i64});
        assert!(canonical_json(&big_int).is_err());
        let fine = serde_json::json!({"t": 0.00001f64});
        assert_eq!(canonical_json(&fine).unwrap(), r#"{"t":0.00001}"#);
        let max_int = serde_json::json!({"t": 9_007_199_254_740_991i64});
        assert_eq!(canonical_json(&max_int).unwrap(), r#"{"t":9007199254740991}"#);
    }

    #[test]
    fn contact_is_in_the_hash() {
        let with = parse_packet(
            r#"{
          "spec":"rivlet-packet/0.0.1",
          "packet_id":"pkt_xcontact01",
          "revision":1,
          "created_at":"2026-09-08T15:12:00.000Z",
          "buyer":{"name":"Northline Equipment","contact":"buyer@northline.example"},
          "part":{"family":"CNC bracket","part_number":"NL-BRK-4410","material":{"spec":"6061-T6"},"qty":{"target":50}},
          "need_by":"2026-10-24",
          "incoterms":"FOB",
          "itar":false
        }"#,
        )
        .unwrap();
        let without = parse_packet(
            r#"{
          "spec":"rivlet-packet/0.0.1",
          "packet_id":"pkt_xcontact01",
          "revision":1,
          "created_at":"2026-09-08T15:12:00.000Z",
          "buyer":{"name":"Northline Equipment"},
          "part":{"family":"CNC bracket","part_number":"NL-BRK-4410","material":{"spec":"6061-T6"},"qty":{"target":50}},
          "need_by":"2026-10-24",
          "incoterms":"FOB",
          "itar":false
        }"#,
        )
        .unwrap();
        assert_ne!(packet_hash(&with).unwrap(), packet_hash(&without).unwrap());
    }

    #[test]
    fn itar_packet_rejects_non_itar_seller() {
        let json = r#"{
          "spec":"rivlet-packet/0.0.1",
          "packet_id":"pkt_itarfail01",
          "revision":1,
          "created_at":"2026-09-08T15:12:00.000Z",
          "buyer":{"name":"Northline Equipment"},
          "part":{"family":"CNC bracket","part_number":"NL-BRK-4410","material":{"spec":"6061-T6"},"qty":{"target":50}},
          "itar":true,
          "quotes":[{
            "quote_id":"qte_notitar01",
            "seller":{"name":"Red River Machine","itar":false},
            "packet_hash_quoted":"sha384:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at":"2026-09-09T00:00:00.000Z",
            "valid_until":"2026-09-30T00:00:00.000Z",
            "lead_time_days":12,
            "pricing":{"currency":"USD","lines":[{"qty":50,"unit":29}]}
          }]
        }"#;
        assert!(parse_packet(json).is_err());
    }

    #[test]
    fn negative_unit_is_not_bound() {
        let packet = parse_packet(
            r#"{
          "spec":"rivlet-packet/0.0.1",
          "packet_id":"pkt_negprice01",
          "revision":1,
          "created_at":"2026-09-08T15:12:00.000Z",
          "buyer":{"name":"Northline Equipment"},
          "part":{"family":"CNC bracket","part_number":"NL-BRK-4410","material":{"spec":"6061-T6"},"qty":{"target":50}},
          "itar":false,
          "quotes":[{
            "quote_id":"qte_negunit01",
            "seller":{"name":"Huron Precision","itar":true},
            "packet_hash_quoted":"sha384:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at":"2026-09-09T00:00:00.000Z",
            "valid_until":"2026-09-30T00:00:00.000Z",
            "lead_time_days":12,
            "pricing":{"currency":"USD","lines":[{"qty":50,"unit":-29}]}
          }]
        }"#,
        )
        .unwrap();
        assert!(bound_quotes(&packet).is_empty());
    }

    #[test]
    fn rfc3339_millis_parses_desk_timestamps() {
        assert_eq!(rfc3339_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_millis("1970-01-01T00:00:00.000Z"), Some(0));
        assert!(rfc3339_millis("2026-09-30T00:00:00.000Z").unwrap() > 0);
    }
}
