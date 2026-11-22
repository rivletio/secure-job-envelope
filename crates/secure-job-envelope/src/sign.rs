//! Post-quantum authorship signatures — CNSA 2.0 profile (ML-DSA-87, FIPS 204).
//!
//! Mirrors `src/lib/traveler/signature.ts` byte-for-byte: the signed message is
//! `domain ‖ 0x00 ‖ canonical_body`, signed with the deterministic ML-DSA
//! variant (rnd = 0), so a signature produced by the TypeScript reference
//! verifies here and vice versa. The shared `conformance/signatures/*` vectors
//! pin this agreement across the two independent codebases.

use crate::canonical_json;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, SigningKey, VerifyingKey, B32,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha384};

pub const SIG_ALG: &str = "ML-DSA-87";
pub const DOMAIN_TRAVELER: &str = "sje-sig/traveler/0.1.0";
pub const DOMAIN_QUOTE: &str = "sje-sig/quote/0.1.0";
pub const DOMAIN_AWARD: &str = "sje-sig/award/0.1.0";
pub const DOMAIN_DIRECTORY: &str = "sje-sig/directory/0.1.0";
pub const DOMAIN_PREKEYS: &str = "sje-sig/prekeys/0.1.0";

/// Bytes actually signed: the domain tag, a NUL, then the canonical body.
fn signed_message(domain: &str, canonical_body: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 1 + canonical_body.len());
    m.extend_from_slice(domain.as_bytes());
    m.push(0);
    m.extend_from_slice(canonical_body.as_bytes());
    m
}

/// Deterministic keypair from a 32-byte seed. Returns (public_key_hex, signing_key).
pub fn keypair_from_seed(seed: &[u8; 32]) -> (String, SigningKey<MlDsa87>) {
    let sk = SigningKey::<MlDsa87>::from_seed(&B32::from(*seed));
    let pk_hex = hex::encode(sk.verifying_key().encode().as_slice());
    (pk_hex, sk)
}

/// Deterministic ML-DSA-87 signature (lowercase hex) over the domain-separated body.
pub fn sign_body(domain: &str, canonical_body: &str, sk: &SigningKey<MlDsa87>) -> String {
    let sig: Signature<MlDsa87> = sk.sign(&signed_message(domain, canonical_body));
    hex::encode(sig.encode().as_slice())
}

/// Verify a hex ML-DSA-87 signature over the domain-separated body against a hex public key.
/// Any malformed input (bad hex, wrong length, bad signature) verifies as false.
pub fn verify_body(domain: &str, canonical_body: &str, sig_hex: &str, pk_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(pk_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(pk_arr) = EncodedVerifyingKey::<MlDsa87>::try_from(&pk_bytes[..]) else {
        return false;
    };
    let Ok(sig_arr) = EncodedSignature::<MlDsa87>::try_from(&sig_bytes[..]) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&pk_arr);
    let Some(sig) = Signature::<MlDsa87>::decode(&sig_arr) else {
        return false;
    };
    vk.verify(&signed_message(domain, canonical_body), &sig).is_ok()
}

pub const DIRECTORY_SPEC: &str = "sje-directory/0.1.0";
pub const PREKEY_BUNDLE_SPEC: &str = "sje-prekeys/0.1.0";
/// Most entries one directory may carry.
pub const MAX_DIRECTORY_ENTRIES: usize = 512;
/// A directory's JSON text, in bytes (an entry is ~9 KB of key material).
pub const MAX_DIRECTORY_JSON_BYTES: usize = 8 * 1024 * 1024;
/// Most one-time prekeys one bundle may carry.
pub const MAX_BUNDLE_PREKEYS: usize = 256;
/// A prekey bundle's JSON text, in bytes.
pub const MAX_PREKEY_BUNDLE_JSON_BYTES: usize = 1024 * 1024;
const KEM_ALG: &str = "ML-KEM-1024";
const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;
const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;
const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1568;

// ---------------------------------------------------------------------------
// Shape. A signature says who signed the bytes; it does not say every reader takes
// the same meaning from them. A root-signed directory with `entries: [null]`, a
// capability spelled `"itar": "false"`, one kid on two orgs, or a key of the wrong
// length used to be read by each implementation in its own way. So the directory and
// the prekey bundle have an exact shape, identical to the TypeScript reference
// (`directory.ts` `directoryShapeError`, `prekeys.ts` `prekeyBundleShapeError`), and
// the text is read strictly (no repeated member name, size-capped).
// ---------------------------------------------------------------------------

/// The object `v` iff its members all come from `required ∪ optional` and include
/// every one of `required`.
fn members<'a>(v: &'a Value, required: &[&str], optional: &[&str]) -> Option<&'a Map<String, Value>> {
    let m = v.as_object()?;
    let ok = required.iter().all(|k| m.contains_key(*k))
        && m.keys().all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()));
    ok.then_some(m)
}

/// Lowercase hex of exactly `bytes` bytes.
fn hex_of(v: &Value, bytes: usize) -> Option<&str> {
    let s = v.as_str()?;
    (s.len() == 2 * bytes && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then_some(s)
}

/// A key id, root id or prekey id: 1–64 of `[A-Za-z0-9._-]`.
fn key_id(v: &Value) -> Option<&str> {
    let s = v.as_str()?;
    let ok = (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some(s)
}

fn org_id(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| crate::validate::org_id_ok(s))
}

/// `[from, until)` as instants, iff both are canonical datetimes with from < until.
fn window(from: &Value, until: &Value) -> Option<(i64, i64)> {
    let a = crate::rfc3339_millis(from.as_str()?)?;
    let b = crate::rfc3339_millis(until.as_str()?)?;
    (a < b).then_some((a, b))
}

struct Entry {
    org_id: String,
    kid: String,
    public_key: String,
    from: i64,
    until: i64,
    active: bool,
    itar: bool,
    enc_public_key: Option<String>,
}

impl Entry {
    /// Usable at `at_ms`: active and inside `[valid_from, valid_until)`.
    fn usable(&self, at_ms: i64) -> bool {
        self.active && self.from <= at_ms && at_ms < self.until
    }
}

/// A shape-valid directory. Whether it is *trusted* is `load_directory`'s business.
struct Directory {
    issued: i64,
    until: i64,
    sig: String,
    entries: Vec<Entry>,
}

impl Directory {
    /// The usable entry with this kid. A kid is on at most one entry.
    fn by_kid(&self, kid: &str, at_ms: i64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.kid == kid && e.usable(at_ms))
    }

    /// Whether any usable entry of the org attests ITAR (order-independent).
    fn has_itar(&self, org: &str, at_ms: i64) -> bool {
        self.entries.iter().any(|e| e.org_id == org && e.usable(at_ms) && e.itar)
    }

    /// The entry to ENCRYPT to for an org: among its usable entries carrying an
    /// encryption key, the one whose validity started most recently (ties: the greater
    /// kid) — never "whichever is listed first".
    fn encryption_entry(&self, org: &str, at_ms: i64) -> Option<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.org_id == org && e.usable(at_ms) && e.enc_public_key.is_some())
            .max_by(|a, b| a.from.cmp(&b.from).then_with(|| a.kid.cmp(&b.kid)))
    }
}

fn directory_from(v: &Value) -> Result<Directory, &'static str> {
    let d = members(v, &["spec", "issued_at", "valid_until", "root_kid", "entries", "sig"], &[])
        .ok_or("unexpected or missing members")?;
    if d["spec"].as_str() != Some(DIRECTORY_SPEC) {
        return Err("unsupported spec");
    }
    let (issued, until) = window(&d["issued_at"], &d["valid_until"]).ok_or("issued_at / valid_until")?;
    key_id(&d["root_kid"]).ok_or("root_kid")?;
    let sig = hex_of(&d["sig"], ML_DSA_87_SIGNATURE_BYTES).ok_or("sig")?.to_string();
    let list = d["entries"].as_array().filter(|l| l.len() <= MAX_DIRECTORY_ENTRIES).ok_or("entries")?;
    let mut entries: Vec<Entry> = Vec::with_capacity(list.len());
    for raw in list {
        let e = members(
            raw,
            &["org_id", "kid", "alg", "public_key", "valid_from", "valid_until", "status"],
            &["capabilities", "enc_alg", "enc_public_key"],
        )
        .ok_or("entry has unexpected or missing members")?;
        let org = org_id(&e["org_id"]).ok_or("entry org_id")?;
        let kid = key_id(&e["kid"]).ok_or("entry kid")?;
        if entries.iter().any(|x| x.kid == kid) {
            return Err("entry kid repeats an earlier entry");
        }
        if e["alg"].as_str() != Some(SIG_ALG) {
            return Err("entry alg");
        }
        let public_key = hex_of(&e["public_key"], ML_DSA_87_PUBLIC_KEY_BYTES).ok_or("entry public_key")?;
        let (from, until) = window(&e["valid_from"], &e["valid_until"]).ok_or("entry valid_from / valid_until")?;
        let active = match e["status"].as_str() {
            Some("active") => true,
            Some("revoked") => false,
            _ => return Err("entry status"),
        };
        let itar = match e.get("capabilities") {
            None => false,
            Some(c) => {
                let c = members(c, &[], &["itar"]).ok_or("entry capabilities")?;
                match c.get("itar") {
                    None => false,
                    Some(b) => b.as_bool().ok_or("entry capabilities.itar")?,
                }
            }
        };
        let enc_public_key = match (e.get("enc_alg"), e.get("enc_public_key")) {
            (None, None) => None,
            (Some(alg), Some(key)) => {
                if alg.as_str() != Some(KEM_ALG) {
                    return Err("entry enc_alg");
                }
                Some(hex_of(key, ML_KEM_1024_PUBLIC_KEY_BYTES).ok_or("entry enc_public_key")?.to_string())
            }
            _ => return Err("entry enc_alg / enc_public_key"),
        };
        entries.push(Entry {
            org_id: org.to_string(),
            kid: kid.to_string(),
            public_key: public_key.to_string(),
            from,
            until,
            active,
            itar,
            enc_public_key,
        });
    }
    Ok(Directory { issued, until, sig, entries })
}

/// Strictly read directory text: size-capped, no repeated member name, exact shape.
fn read_directory(dir_json: &str) -> Result<(Value, Directory), &'static str> {
    if dir_json.len() > MAX_DIRECTORY_JSON_BYTES {
        return Err("directory exceeds the size limit");
    }
    let v = crate::de::strict_value(dir_json).map_err(|_| "directory is not strict JSON")?;
    let dir = directory_from(&v)?;
    Ok((v, dir))
}

/// Check that `dir_json` is exactly a well-formed signed directory, without using any
/// key. The error names the rule that failed; nothing from the directory is echoed.
pub fn directory_shape(dir_json: &str) -> Result<(), &'static str> {
    read_directory(dir_json).map(|_| ())
}

/// The directory, iff it is well-formed, `at_ms` is inside its own freshness window
/// `[issued_at, valid_until)`, and its signature verifies against the trust root.
fn load_directory(dir_json: &str, root_pk_hex: &str, at_ms: i64) -> Option<Directory> {
    let (mut v, dir) = read_directory(dir_json).ok()?;
    if !(dir.issued <= at_ms && at_ms < dir.until) {
        return None;
    }
    // The signed body is the directory with its own `sig` removed, canonicalized —
    // identical bytes to the TypeScript `directoryBody`.
    v.as_object_mut()?.remove("sig");
    let canonical = canonical_json(&v).ok()?;
    verify_body(DOMAIN_DIRECTORY, &canonical, &dir.sig, root_pk_hex).then_some(dir)
}

/// Verify a signed key directory (JSON) against the trust-root public key (hex): it
/// has exactly the specified shape, `at_ms` falls within its own freshness window
/// `[issued_at, valid_until)`, and the root's signature verifies. The window is part
/// of the signed body, so it cannot be widened without breaking the root signature;
/// enforcing it here additionally bounds how long a stale (but validly-signed)
/// directory can be replayed. False on any malformed or out-of-window input.
pub fn verify_directory(dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    load_directory(dir_json, root_pk_hex, at_ms).is_some()
}

/// Look up a directory entry by kid that is active and in its validity window at
/// `at_ms`, returning (org_id, public_key_hex). None for a malformed directory. Does
/// NOT check the root signature — call `verify_directory` first.
pub fn directory_entry_by_kid(dir_json: &str, kid: &str, at_ms: i64) -> Option<(String, String)> {
    let (_, dir) = read_directory(dir_json).ok()?;
    dir.by_kid(kid, at_ms).map(|e| (e.org_id.clone(), e.public_key.clone()))
}

/// The recipient to seal to for an org: `(enc_kid, ml_kem_public_key_hex)` of the
/// org's most recently started usable entry that carries an encryption key. None if
/// there is none or the directory is malformed. Does NOT check the root signature —
/// call `verify_directory` first. Mirrors the TypeScript `recipientByOrg`.
pub fn recipient_by_org(dir_json: &str, org: &str, at_ms: i64) -> Option<(String, String)> {
    let (_, dir) = read_directory(dir_json).ok()?;
    let key = dir.encryption_entry(org, at_ms)?.enc_public_key.clone()?;
    Some((crate::envelope::enc_kid(&key)?, key))
}

// ---------------------------------------------------------------------------
// Verification. Reasons are the same strings the TypeScript reference returns, so the
// shared cases (conformance/signatures/verify-cases.json) pin not only that a document
// is refused but which rule refused it, on both sides.
// ---------------------------------------------------------------------------

/// The result of checking one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub ok: bool,
    /// The kid the signature names ("" when there is no signature to name one).
    pub kid: String,
    /// The org the directory binds that kid to, when the kid resolved.
    pub org_id: Option<String>,
    /// Why it was refused; None when `ok`.
    pub reason: Option<&'static str>,
}

impl Check {
    fn refused(kid: &str, reason: &'static str) -> Self {
        Check { ok: false, kid: kid.to_string(), org_id: None, reason: Some(reason) }
    }
    fn but(mut self, reason: &'static str) -> Self {
        self.ok = false;
        self.reason = Some(reason);
        self
    }
}

const R_DIRECTORY: &str = "directory does not verify against the trust root";
const R_TRAVELER: &str = "not a valid traveler";
const R_QUOTE: &str = "not a valid quote";

/// Check one signature: the kid must resolve to a usable directory entry, that entry's
/// org must be the org the document names as its author, and the key must verify the
/// domain-separated body.
fn check_sig(
    dir: &Directory,
    domain: &str,
    canonical_body: &str,
    sig: &crate::Signature,
    claimed_org: Option<&str>,
    at_ms: i64,
) -> Check {
    let Some(claimed) = claimed_org else {
        return Check::refused(&sig.kid, "author names no org_id to bind the signature to");
    };
    let Some(entry) = dir.by_kid(&sig.kid, at_ms) else {
        return Check::refused(&sig.kid, "no active in-window directory entry for kid");
    };
    let named = Check { ok: false, kid: sig.kid.clone(), org_id: Some(entry.org_id.clone()), reason: None };
    if entry.org_id != claimed {
        return named.but("signer org does not match author org");
    }
    if !verify_body(domain, canonical_body, &sig.sig, &entry.public_key) {
        return named.but("signature does not verify");
    }
    Check { ok: true, ..named }
}

/// The canonical bytes of `v` with its own `sig` member removed.
fn body_without_sig(v: &Value) -> Option<String> {
    let mut body = v.clone();
    body.as_object_mut()?.remove("sig");
    canonical_json(&body).ok()
}

/// What verification established about a traveler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// One check per buyer signature on the traveler (empty: unsigned). A directory
    /// that does not verify, or a document that is not a valid traveler, yields a
    /// single refused check saying so.
    pub authorship: Vec<Check>,
    /// The buyer's award signature: None iff the traveler carries no award.
    pub award: Option<Check>,
    /// Per quote, in document order: its id and its seller-signature check (None:
    /// the quote is unsigned).
    pub quotes: Vec<(String, Option<Check>)>,
}

impl Report {
    /// At least one valid buyer signature.
    pub fn authored(&self) -> bool {
        self.authorship.iter().any(|c| c.ok)
    }
    /// The traveler is the buyer's and, if it carries an award, so is the award.
    pub fn verified(&self) -> bool {
        self.authored() && self.award.as_ref().map_or(true, |a| a.ok)
    }
}

/// Verify everything a traveler carries — buyer authorship, the award, each quote's
/// seller signature — against a signed directory at `at_ms`. Mirrors the TypeScript
/// `verifyTravelerSignatures` / `verifyAwardSignature` / `verifyQuoteSignature`.
pub fn verify_report(traveler_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> Report {
    // Whether an award is present is read from the document as written, before
    // anything else, so "no award" stays distinct from "an award that failed".
    let raw = crate::de::strict_value(traveler_json).ok();
    let has_award = match &raw {
        Some(v) => v.get("award").is_some_and(|a| !a.is_null()),
        None => true, // unreadable: nothing is established, including "no award"
    };
    let all = |reason: &'static str| Report {
        authorship: vec![Check::refused("", reason)],
        award: has_award.then(|| Check::refused("", reason)),
        quotes: Vec::new(),
    };
    let Some(dir) = load_directory(dir_json, root_pk_hex, at_ms) else {
        return all(R_DIRECTORY);
    };
    let (Ok(t), Some(raw)) = (crate::parse_traveler(traveler_json), raw) else {
        return all(R_TRAVELER);
    };
    let buyer_org = t.buyer.org_id.as_deref();

    // Authorship: the canonical quoteable body (== the traveler_hash preimage).
    let quoteable = serde_json::to_value(crate::quoteable_from(&t)).ok().and_then(|v| canonical_json(&v).ok());
    let signatures = t.signatures.as_deref().unwrap_or(&[]);
    let authorship = match &quoteable {
        Some(body) => signatures
            .iter()
            .map(|s| check_sig(&dir, DOMAIN_TRAVELER, body, s, buyer_org, at_ms))
            .collect(),
        None => signatures
            .iter()
            .map(|s| Check::refused(&s.kid, "traveler body is not canonicalizable"))
            .collect(),
    };

    // Quotes. The signed bytes are built from the document AS WRITTEN (minus `sig`).
    // That is sound only because parse_traveler has already held it to the strict
    // schema: no unknown or repeated members, no positional structs, no normalizing
    // transform — so the raw and the typed document carry the same members and values.
    let raw_quotes: &[Value] = raw.get("quotes").and_then(Value::as_array).map_or(&[], Vec::as_slice);
    let quotes = t
        .quotes
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .zip(raw_quotes)
        .map(|(q, raw_q)| {
            let check = q.sig.as_ref().map(|sig| match body_without_sig(raw_q) {
                Some(body) => check_sig(&dir, DOMAIN_QUOTE, &body, sig, q.seller.org_id.as_deref(), at_ms),
                None => Check::refused(&sig.kid, "quote body is not canonicalizable"),
            });
            (q.quote_id.clone(), check)
        })
        .collect();

    let award = t.award.as_ref().map(|award| award_check(&dir, &t, &raw, award, raw_quotes, at_ms));
    Report { authorship, award, quotes }
}

/// The buyer's award: signed by the buyer over `{spec, traveler_id, traveler_hash,
/// award (minus sig), ship_to}`, committing — through `quote_hash` — to the content of
/// a quote that is present, was made against this revision, and prices the awarded
/// quantity.
fn award_check(
    dir: &Directory,
    t: &crate::Traveler,
    raw: &Value,
    award: &crate::Award,
    raw_quotes: &[Value],
    at_ms: i64,
) -> Check {
    let Some(sig) = award.sig.as_ref() else {
        return Check::refused("", "award is present but not signed by the buyer");
    };
    let not_canonical = || Check::refused(&sig.kid, "award body is not canonicalizable");
    let Ok(traveler_hash) = crate::traveler_hash(t) else {
        return not_canonical();
    };
    let Some(mut award_value) = raw.get("award").cloned() else {
        return not_canonical();
    };
    if let Some(obj) = award_value.as_object_mut() {
        obj.remove("sig");
    }
    let body = serde_json::json!({
        "spec": raw.get("spec").cloned().unwrap_or(Value::Null),
        "traveler_id": raw.get("traveler_id").cloned().unwrap_or(Value::Null),
        "traveler_hash": traveler_hash,
        "award": award_value,
        "ship_to": raw.get("ship_to").cloned().unwrap_or(Value::Null),
    });
    let Ok(canonical) = canonical_json(&body) else {
        return not_canonical();
    };
    let check = check_sig(dir, DOMAIN_AWARD, &canonical, sig, t.buyer.org_id.as_deref(), at_ms);
    if !check.ok {
        return check;
    }
    // The signature is the buyer's. It must also bind a determinate, priced quote.
    let Some(quote_hash) = award.quote_hash.as_deref() else {
        return check.but("signed award does not bind a quote_hash");
    };
    let quotes = t.quotes.as_deref().unwrap_or(&[]);
    let Some(i) = quotes.iter().position(|q| q.quote_id == award.quote_id) else {
        return check.but("awarded quote is not present to verify its priced content");
    };
    let Some(canon_quote) = raw_quotes.get(i).and_then(body_without_sig) else {
        return check.but("awarded quote body is not canonicalizable");
    };
    if format!("sha384:{}", hex::encode(Sha384::digest(canon_quote.as_bytes()))) != quote_hash {
        return check.but("awarded quote content does not match the buyer-signed quote_hash");
    }
    if quotes[i].traveler_hash_quoted != traveler_hash {
        return check.but("awarded quote is not bound to this revision");
    }
    if !quotes[i].pricing.lines.iter().any(|l| l.qty == award.qty) {
        return check.but("awarded quote has no price for the awarded quantity");
    }
    check
}

/// True iff the directory verifies and at least one of the traveler's signatures is a
/// valid buyer-authorship signature (see `verify_report`).
pub fn verify_traveler_authorship(traveler_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    verify_report(traveler_json, dir_json, root_pk_hex, at_ms).authored()
}

/// True iff the traveler carries an award and it verifies as the buyer's, bound to a
/// present, current, priced quote (see `verify_report`). False for a missing award —
/// use `verify_report` to tell "no award" from "an award that failed".
pub fn verify_award_signature(traveler_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    verify_report(traveler_json, dir_json, root_pk_hex, at_ms).award.is_some_and(|c| c.ok)
}

/// Check a standalone quote's seller signature. None iff the quote is valid and
/// unsigned; otherwise the check (refused if the directory does not verify or the
/// document is not a valid quote).
pub fn quote_check(quote_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> Option<Check> {
    let Some(dir) = load_directory(dir_json, root_pk_hex, at_ms) else {
        return Some(Check::refused("", R_DIRECTORY));
    };
    quote_check_in(&dir, quote_json, at_ms)
}

fn quote_check_in(dir: &Directory, quote_json: &str, at_ms: i64) -> Option<Check> {
    let (Ok(q), Ok(raw)) = (crate::parse_quote(quote_json), crate::de::strict_value(quote_json)) else {
        return Some(Check::refused("", R_QUOTE));
    };
    let sig = q.sig.as_ref()?;
    Some(match body_without_sig(&raw) {
        Some(body) => check_sig(dir, DOMAIN_QUOTE, &body, sig, q.seller.org_id.as_deref(), at_ms),
        None => Check::refused(&sig.kid, "quote body is not canonicalizable"),
    })
}

/// True iff the quote carries a seller signature that verifies (see `quote_check`).
pub fn verify_quote_signature(quote_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    quote_check(quote_json, dir_json, root_pk_hex, at_ms).is_some_and(|c| c.ok)
}

/// ITAR gate elevated to directory attestation (caveat 3). None if the quote is
/// allowed; Some(reason) if refused. An ITAR traveler's seller must hold the ITAR
/// capability in a directory that verifies against the trust root — and the quote must
/// be SIGNED by that seller: `seller.org_id` is a field the quote's author types, so
/// without a verified signature an unsigned quote that merely names an attested org
/// passed this gate. Fails closed on any malformed input (a traveler that does not
/// parse is refused, not treated as "not ITAR"). Mirrors the TypeScript
/// `itarAttestationBlocker`, reason for reason.
pub fn itar_attestation_blocker(
    traveler_json: &str,
    quote_json: &str,
    dir_json: &str,
    root_pk_hex: &str,
    at_ms: i64,
) -> Option<String> {
    let Ok(t) = crate::parse_traveler(traveler_json) else {
        return Some("ITAR gate: not a valid traveler".into());
    };
    if t.itar != Some(true) {
        return None; // a non-ITAR traveler imposes no gate
    }
    let Some(dir) = load_directory(dir_json, root_pk_hex, at_ms) else {
        return Some("ITAR traveler: key directory does not verify against the trust root".into());
    };
    let Ok(q) = crate::parse_quote(quote_json) else {
        return Some("ITAR gate: not a valid quote".into());
    };
    let Some(seller_org) = q.seller.org_id.as_deref() else {
        return Some("ITAR traveler: seller has no org_id to attest against the directory".into());
    };
    if !quote_check_in(&dir, quote_json, at_ms).is_some_and(|c| c.ok) {
        return Some("ITAR traveler: quote is not signed by the seller it names".into());
    }
    if !dir.has_itar(seller_org, at_ms) {
        return Some("ITAR traveler: seller is not attested for ITAR in the directory".into());
    }
    None
}

/// Check that `bundle_json` is exactly a well-formed signed prekey bundle, without
/// using any key. Mirrors the TypeScript `prekeyBundleShapeError`.
pub fn prekey_bundle_shape(bundle_json: &str) -> Result<(), &'static str> {
    read_bundle(bundle_json).map(|_| ())
}

struct Bundle {
    org_id: String,
    kid: String,
    issued: i64,
    until: i64,
    sig: String,
}

fn read_bundle(bundle_json: &str) -> Result<(Value, Bundle), &'static str> {
    if bundle_json.len() > MAX_PREKEY_BUNDLE_JSON_BYTES {
        return Err("prekey bundle exceeds the size limit");
    }
    let v = crate::de::strict_value(bundle_json).map_err(|_| "prekey bundle is not strict JSON")?;
    let b = members(
        &v,
        &["spec", "org_id", "kid", "enc_alg", "issued_at", "valid_until", "prekeys", "sig"],
        &[],
    )
    .ok_or("unexpected or missing members")?;
    if b["spec"].as_str() != Some(PREKEY_BUNDLE_SPEC) {
        return Err("unsupported spec");
    }
    let org = org_id(&b["org_id"]).ok_or("org_id")?.to_string();
    let kid = key_id(&b["kid"]).ok_or("kid")?.to_string();
    if b["enc_alg"].as_str() != Some(KEM_ALG) {
        return Err("enc_alg");
    }
    let (issued, until) = window(&b["issued_at"], &b["valid_until"]).ok_or("issued_at / valid_until")?;
    let sig = hex_of(&b["sig"], ML_DSA_87_SIGNATURE_BYTES).ok_or("sig")?.to_string();
    let prekeys = b["prekeys"].as_array().filter(|l| l.len() <= MAX_BUNDLE_PREKEYS).ok_or("prekeys")?;
    let mut ids: Vec<&str> = Vec::with_capacity(prekeys.len());
    for raw in prekeys {
        let p = members(raw, &["prekey_id", "public_key"], &[]).ok_or("prekey has unexpected or missing members")?;
        let id = key_id(&p["prekey_id"]).ok_or("prekey prekey_id")?;
        if ids.contains(&id) {
            return Err("prekey prekey_id repeats an earlier prekey");
        }
        ids.push(id);
        hex_of(&p["public_key"], ML_KEM_1024_PUBLIC_KEY_BYTES).ok_or("prekey public_key")?;
    }
    let bundle = Bundle { org_id: org, kid, issued, until, sig };
    Ok((v, bundle))
}

/// Verify a signed one-time prekey bundle (JSON) against the signed directory at
/// `at_ms`: the bundle has exactly the specified shape, the directory verifies against
/// the root, the bundle's own [issued_at, valid_until) covers at_ms, its signing kid
/// resolves (active, in-window) to an entry whose org equals the bundle's org_id, and
/// the ML-DSA signature over the canonical body (bundle minus its own sig) checks out.
/// False on any failure. Mirrors the TypeScript verifyPrekeyBundle.
pub fn verify_prekey_bundle(bundle_json: &str, dir_json: &str, root_pk_hex: &str, at_ms: i64) -> bool {
    (|| -> Option<bool> {
        let (mut v, bundle) = read_bundle(bundle_json).ok()?;
        let dir = load_directory(dir_json, root_pk_hex, at_ms)?;
        if !(bundle.issued <= at_ms && at_ms < bundle.until) {
            return None;
        }
        let entry = dir.by_kid(&bundle.kid, at_ms).filter(|e| e.org_id == bundle.org_id)?;
        v.as_object_mut()?.remove("sig");
        let canonical = canonical_json(&v).ok()?;
        Some(verify_body(DOMAIN_PREKEYS, &canonical, &bundle.sig, &entry.public_key))
    })()
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_separation() {
        let (pk, sk) = keypair_from_seed(&[7u8; 32]);
        let body = r#"{"a":1}"#;
        let sig = sign_body(DOMAIN_TRAVELER, body, &sk);
        assert!(verify_body(DOMAIN_TRAVELER, body, &sig, &pk));
        // tampered body, wrong domain, wrong key all fail
        assert!(!verify_body(DOMAIN_TRAVELER, r#"{"a":2}"#, &sig, &pk));
        assert!(!verify_body(DOMAIN_QUOTE, body, &sig, &pk));
        let (pk2, _) = keypair_from_seed(&[9u8; 32]);
        assert!(!verify_body(DOMAIN_TRAVELER, body, &sig, &pk2));
        // malformed inputs are false, never panic
        assert!(!verify_body(DOMAIN_TRAVELER, body, "zz", &pk));
        assert!(!verify_body(DOMAIN_TRAVELER, body, &sig, "00"));
    }

    #[test]
    fn signing_is_deterministic() {
        let (_, sk) = keypair_from_seed(&[3u8; 32]);
        let a = sign_body(DOMAIN_QUOTE, r#"{"x":9}"#, &sk);
        let b = sign_body(DOMAIN_QUOTE, r#"{"x":9}"#, &sk);
        assert_eq!(a, b);
    }
}
