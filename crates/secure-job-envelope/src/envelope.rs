//! Encrypted envelope — CNSA 2.0 profile (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM).
//!
//! Mirrors `src/lib/traveler/envelope.ts` byte-for-byte: a random CEK encrypts
//! the payload once; per recipient an ML-KEM-1024 encapsulation yields a shared
//! secret, HKDF-SHA-384 derives a KEK, and the CEK is wrapped under it with
//! AES-256-GCM. AAD binds {spec, enc_alg} to the payload and {spec, enc_alg, kid}
//! to each wrap. The shared conformance vector proves the two implementations
//! agree on every byte.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey, MlKem1024, Seed, B32};
use serde_json::Value;
use sha2::{Digest, Sha384};

pub const ENVELOPE_SPEC: &str = "sje-envelope/0.1.0";
pub const ENC_ALG: &str = "ML-KEM-1024+HKDF-SHA-384+AES-256-GCM";
const KEK_SALT: &[u8] = b"sje-kek/0.1.0";

/// Payload AAD binds the algorithm identifiers AND the ordered recipient set
/// (as canonical JSON), so a downgraded alg or a dropped/reordered/duplicated
/// recipient breaks the payload tag. Mirrors the TypeScript aadPayload.
fn aad_payload(recipient_kids: &[&str]) -> Vec<u8> {
    let v = serde_json::json!({
        "spec": ENVELOPE_SPEC,
        "enc_alg": ENC_ALG,
        "recipients": recipient_kids,
    });
    crate::canonical_json(&v)
        .expect("canonical payload aad")
        .into_bytes()
}

/// Opaque recipient id derived from an ML-KEM public key (hex): the first 16 hex
/// chars of its SHA-384. Mirrors the TypeScript `encKid`. None on bad hex.
pub fn enc_kid(enc_public_key_hex: &str) -> Option<String> {
    let bytes = hex::decode(enc_public_key_hex).ok()?;
    let digest = Sha384::digest(&bytes);
    Some(hex::encode(digest)[..16].to_string())
}
fn aad_recipient(kid: &str) -> Vec<u8> {
    format!("{ENVELOPE_SPEC}\0{ENC_ALG}\0{kid}").into_bytes()
}
fn kek(shared_secret: &[u8], kid: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha384>::new(Some(KEK_SALT), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(&aad_recipient(kid), &mut okm).expect("hkdf expand");
    okm
}
fn gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let c = Aes256Gcm::new_from_slice(key).expect("aes key");
    let n = Nonce::try_from(&nonce[..]).expect("nonce");
    c.encrypt(&n, Payload { msg: pt, aad }).expect("aes-gcm encrypt")
}
fn gcm_decrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    let n = Nonce::try_from(nonce).ok()?;
    c.decrypt(&n, Payload { msg: ct, aad }).ok()
}

/// Deterministic single-recipient seal, from the recipient's 64-byte ML-KEM seed.
/// Returns (kem_ct_hex, wrapped_cek_hex, payload_hex) for byte-exact cross-language
/// comparison against the TypeScript reference.
#[allow(clippy::too_many_arguments)]
pub fn seal_deterministic_fields(
    plaintext: &[u8],
    recipient_seed: &[u8; 64],
    kid: &str,
    cek: &[u8; 32],
    payload_nonce: &[u8; 12],
    coins: &[u8; 32],
    wrap_nonce: &[u8; 12],
) -> (String, String, String) {
    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*recipient_seed));
    let (ct, ss) = dk.encapsulation_key().encapsulate_deterministic(&B32::from(*coins));
    let payload = gcm_encrypt(cek, payload_nonce, &aad_payload(&[kid]), plaintext);
    let wrapped = gcm_encrypt(&kek(ss.as_slice(), kid), wrap_nonce, &aad_recipient(kid), cek);
    (
        hex::encode(ct.as_slice()),
        hex::encode(&wrapped),
        hex::encode(&payload),
    )
}

// ---------------------------------------------------------------------------
// Wire shape — what an envelope must look like before any key touches it.
//
// AES-GCM authenticates the payload and each wrapped key, but not the JSON around
// them: an extra member, a hex string in the other letter case, a 13-byte nonce or a
// 16-byte content key are outside what the tags cover or decide. The shape is
// therefore exact, and identical to the TypeScript reference
// (`src/lib/traveler/envelope.ts` `assertEnvelopeShape`):
//
//   envelope   exactly { spec, enc_alg, payload_nonce, payload, recipients }
//   recipient  0.1.0: exactly { kid, kem_ct, wrap_nonce, wrapped_cek }
//              0.2.0: exactly { kid, prekey_id, kem_ct_onetime, kem_ct_static,
//                               wrap_nonce, wrapped_cek }
//   hex        lowercase, exact byte lengths: nonces 12, kid 8, ML-KEM-1024
//              ciphertext 1568, wrapped key 48 (32-byte key + 16-byte tag);
//              payload at least its 16-byte tag, at most a maximal archive + tag
//   prekey_id  1–64 of [A-Za-z0-9._-]
//   recipients 1–16 entries, no kid twice
//
// The text itself is read strictly: UTF-8 with no byte-order mark, no repeated
// member name at any depth, at most MAX_ENVELOPE_JSON_BYTES.
// ---------------------------------------------------------------------------

const MAX_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;
/// Most recipient entries one envelope may carry.
pub const MAX_ENVELOPE_RECIPIENTS: usize = 16;
/// An envelope's JSON text, in bytes: the hex of a maximal archive plus room for the
/// recipient entries.
pub const MAX_ENVELOPE_JSON_BYTES: usize = 2 * MAX_ARCHIVE_BYTES + 128 * 1024;
const NONCE_BYTES: usize = 12;
const KID_BYTES: usize = 8;
const KEM_CT_BYTES: usize = 1568;
const WRAPPED_CEK_BYTES: usize = 32 + 16;
const GCM_TAG_BYTES: usize = 16;

struct Recipient {
    kid: String,
    /// `Some` in a 0.2.0 envelope.
    prekey_id: Option<String>,
    /// The ciphertext to the static identity key (`kem_ct` / `kem_ct_static`).
    kem_ct_static: Vec<u8>,
    /// `Some` in a 0.2.0 envelope.
    kem_ct_onetime: Option<Vec<u8>>,
    wrap_nonce: Vec<u8>,
    wrapped_cek: Vec<u8>,
}

struct Shaped {
    forward_secret: bool,
    payload_nonce: Vec<u8>,
    payload: Vec<u8>,
    recipients: Vec<Recipient>,
}

/// The object `v` iff it carries exactly `members` — no more, no fewer.
fn exactly<'a>(v: &'a Value, members: &[&str]) -> Option<&'a serde_json::Map<String, Value>> {
    let m = v.as_object()?;
    (m.len() == members.len() && members.iter().all(|k| m.contains_key(*k))).then_some(m)
}

/// Lowercase hex of `min..=max` bytes, decoded.
fn hex_bytes(v: &Value, min: usize, max: usize) -> Option<Vec<u8>> {
    let s = v.as_str()?;
    let ok = s.len() % 2 == 0
        && s.len() >= 2 * min
        && s.len() <= 2 * max
        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ok { hex::decode(s).ok() } else { None }
}

fn prekey_id_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn shaped(envelope_json: &str) -> Result<Shaped, &'static str> {
    if envelope_json.len() > MAX_ENVELOPE_JSON_BYTES {
        return Err("envelope exceeds the size limit");
    }
    let v = crate::de::strict_value(envelope_json).map_err(|_| "envelope is not strict JSON")?;
    let env = exactly(&v, &["spec", "enc_alg", "payload_nonce", "payload", "recipients"])
        .ok_or("unexpected or missing members")?;
    let forward_secret = match env["spec"].as_str() {
        Some(ENVELOPE_SPEC) => false,
        Some(FS_ENVELOPE_SPEC) => true,
        _ => return Err("unsupported spec"),
    };
    if env["enc_alg"].as_str() != Some(if forward_secret { FS_ENC_ALG } else { ENC_ALG }) {
        return Err("enc_alg does not match spec");
    }
    let payload_nonce = hex_bytes(&env["payload_nonce"], NONCE_BYTES, NONCE_BYTES).ok_or("payload_nonce")?;
    let payload = hex_bytes(&env["payload"], GCM_TAG_BYTES, MAX_ARCHIVE_BYTES + GCM_TAG_BYTES).ok_or("payload")?;
    let list = env["recipients"].as_array().ok_or("recipients")?;
    if list.is_empty() || list.len() > MAX_ENVELOPE_RECIPIENTS {
        return Err("recipients");
    }
    let members: &[&str] = if forward_secret {
        &["kid", "prekey_id", "kem_ct_onetime", "kem_ct_static", "wrap_nonce", "wrapped_cek"]
    } else {
        &["kid", "kem_ct", "wrap_nonce", "wrapped_cek"]
    };
    let mut recipients: Vec<Recipient> = Vec::with_capacity(list.len());
    for entry in list {
        let r = exactly(entry, members).ok_or("recipient has unexpected or missing members")?;
        hex_bytes(&r["kid"], KID_BYTES, KID_BYTES).ok_or("recipient kid")?;
        let kid = r["kid"].as_str().ok_or("recipient kid")?.to_string();
        if recipients.iter().any(|x| x.kid == kid) {
            return Err("recipient kid repeats an earlier recipient");
        }
        let (prekey_id, kem_ct_onetime, static_member) = if forward_secret {
            let id = r["prekey_id"].as_str().filter(|s| prekey_id_ok(s)).ok_or("recipient prekey_id")?;
            let ot = hex_bytes(&r["kem_ct_onetime"], KEM_CT_BYTES, KEM_CT_BYTES).ok_or("recipient kem_ct_onetime")?;
            (Some(id.to_string()), Some(ot), "kem_ct_static")
        } else {
            (None, None, "kem_ct")
        };
        recipients.push(Recipient {
            kid,
            prekey_id,
            kem_ct_static: hex_bytes(&r[static_member], KEM_CT_BYTES, KEM_CT_BYTES).ok_or("recipient kem_ct")?,
            kem_ct_onetime,
            wrap_nonce: hex_bytes(&r["wrap_nonce"], NONCE_BYTES, NONCE_BYTES).ok_or("recipient wrap_nonce")?,
            wrapped_cek: hex_bytes(&r["wrapped_cek"], WRAPPED_CEK_BYTES, WRAPPED_CEK_BYTES)
                .ok_or("recipient wrapped_cek")?,
        });
    }
    Ok(Shaped { forward_secret, payload_nonce, payload, recipients })
}

/// Check that `envelope_json` is exactly a well-formed 0.1.0 or 0.2.0 envelope, without
/// using any key. The error names the rule that failed; nothing from the envelope is
/// echoed.
pub fn check_shape(envelope_json: &str) -> Result<(), &'static str> {
    shaped(envelope_json).map(|_| ())
}

/// Decrypt an envelope (JSON) for the recipient `kid`, using their ML-KEM-1024
/// secret key derived from a 64-byte seed. None on any failure (malformed envelope,
/// unknown kid, tag mismatch), never partial plaintext.
pub fn open(envelope_json: &str, kid: &str, recipient_seed: &[u8; 64]) -> Option<Vec<u8>> {
    let env = shaped(envelope_json).ok().filter(|e| !e.forward_secret)?;
    let kids: Vec<&str> = env.recipients.iter().map(|r| r.kid.as_str()).collect();
    let r = env.recipients.iter().find(|r| r.kid == kid)?;

    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*recipient_seed));
    let ct = Ciphertext::<MlKem1024>::try_from(&r.kem_ct_static[..]).ok()?;
    let ss = dk.decapsulate(&ct);
    let cek_vec = gcm_decrypt(&kek(ss.as_slice(), kid), &r.wrap_nonce, &aad_recipient(kid), &r.wrapped_cek)?;
    let cek: [u8; 32] = cek_vec.try_into().ok()?;
    gcm_decrypt(&cek, &env.payload_nonce, &aad_payload(&kids), &env.payload)
}

// ---------------------------------------------------------------------------
// Forward-secret envelope (sje-envelope/0.2.0) — single-use prekeys, PQXDH-style.
// Encapsulates to BOTH a one-time prekey and the static identity key and binds
// both shared secrets into the KEK. Mirrors src/lib/traveler/envelope.ts.
// ---------------------------------------------------------------------------

pub const FS_ENVELOPE_SPEC: &str = "sje-envelope/0.2.0";
pub const FS_ENC_ALG: &str = "ML-KEM-1024x2+HKDF-SHA-384+AES-256-GCM";

fn aad_payload_fs(recipients: &[(&str, &str)]) -> Vec<u8> {
    let rset: Vec<Value> = recipients
        .iter()
        .map(|(k, p)| serde_json::json!({ "kid": k, "prekey_id": p }))
        .collect();
    let v = serde_json::json!({ "spec": FS_ENVELOPE_SPEC, "enc_alg": FS_ENC_ALG, "recipients": rset });
    crate::canonical_json(&v)
        .expect("canonical fs payload aad")
        .into_bytes()
}
fn aad_recipient_fs(kid: &str, prekey_id: &str) -> Vec<u8> {
    format!("{FS_ENVELOPE_SPEC}\0{FS_ENC_ALG}\0{kid}\0{prekey_id}").into_bytes()
}
/// KEK from BOTH shared secrets (one-time ‖ static); order matches the TS side.
fn fs_kek(ss_onetime: &[u8], ss_static: &[u8], kid: &str, prekey_id: &str) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ss_onetime.len() + ss_static.len());
    ikm.extend_from_slice(ss_onetime);
    ikm.extend_from_slice(ss_static);
    let hk = Hkdf::<Sha384>::new(Some(KEK_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&aad_recipient_fs(kid, prekey_id), &mut okm)
        .expect("hkdf expand");
    okm
}

/// Deterministic single-recipient forward-secret seal, from the recipient's
/// static and one-time 64-byte ML-KEM seeds. Returns
/// (kem_ct_onetime_hex, kem_ct_static_hex, wrapped_cek_hex, payload_hex).
#[allow(clippy::too_many_arguments)]
pub fn seal_fs_deterministic_fields(
    plaintext: &[u8],
    static_seed: &[u8; 64],
    onetime_seed: &[u8; 64],
    kid: &str,
    prekey_id: &str,
    cek: &[u8; 32],
    payload_nonce: &[u8; 12],
    coins_onetime: &[u8; 32],
    coins_static: &[u8; 32],
    wrap_nonce: &[u8; 12],
) -> (String, String, String, String) {
    let dk_ot = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*onetime_seed));
    let (ct_ot, ss_ot) = dk_ot
        .encapsulation_key()
        .encapsulate_deterministic(&B32::from(*coins_onetime));
    let dk_id = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*static_seed));
    let (ct_id, ss_id) = dk_id
        .encapsulation_key()
        .encapsulate_deterministic(&B32::from(*coins_static));
    let payload = gcm_encrypt(cek, payload_nonce, &aad_payload_fs(&[(kid, prekey_id)]), plaintext);
    let kek = fs_kek(ss_ot.as_slice(), ss_id.as_slice(), kid, prekey_id);
    let wrapped = gcm_encrypt(&kek, wrap_nonce, &aad_recipient_fs(kid, prekey_id), cek);
    (
        hex::encode(ct_ot.as_slice()),
        hex::encode(ct_id.as_slice()),
        hex::encode(&wrapped),
        hex::encode(&payload),
    )
}

/// Open a forward-secret envelope (JSON) for `kid`, using the recipient's static
/// and one-time ML-KEM secret keys (each derived from a 64-byte seed). None on any
/// failure. The one-time secret is what the recipient deletes for forward secrecy.
pub fn open_fs(
    envelope_json: &str,
    kid: &str,
    static_seed: &[u8; 64],
    onetime_seed: &[u8; 64],
) -> Option<Vec<u8>> {
    let env = shaped(envelope_json).ok().filter(|e| e.forward_secret)?;
    // `shaped` guarantees prekey_id and kem_ct_onetime are present on every recipient
    // of a forward-secret envelope.
    let rset: Vec<(&str, &str)> = env
        .recipients
        .iter()
        .map(|r| Some((r.kid.as_str(), r.prekey_id.as_deref()?)))
        .collect::<Option<Vec<_>>>()?;
    let r = env.recipients.iter().find(|r| r.kid == kid)?;
    let prekey_id = r.prekey_id.as_deref()?;

    let dk_ot = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*onetime_seed));
    let dk_id = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*static_seed));
    let ct_ot = Ciphertext::<MlKem1024>::try_from(&r.kem_ct_onetime.as_deref()?[..]).ok()?;
    let ct_id = Ciphertext::<MlKem1024>::try_from(&r.kem_ct_static[..]).ok()?;
    let ss_ot = dk_ot.decapsulate(&ct_ot);
    let ss_id = dk_id.decapsulate(&ct_id);
    let kek = fs_kek(ss_ot.as_slice(), ss_id.as_slice(), kid, prekey_id);
    let cek_vec = gcm_decrypt(&kek, &r.wrap_nonce, &aad_recipient_fs(kid, prekey_id), &r.wrapped_cek)?;
    let cek: [u8; 32] = cek_vec.try_into().ok()?;
    gcm_decrypt(&cek, &env.payload_nonce, &aad_payload_fs(&rset), &env.payload)
}
