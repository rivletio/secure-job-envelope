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

/// Decrypt an envelope (JSON) for the recipient `kid`, using their ML-KEM-1024
/// secret key derived from a 64-byte seed. None on any failure (unknown kid,
/// tag mismatch), never partial plaintext.
pub fn open(envelope_json: &str, kid: &str, recipient_seed: &[u8; 64]) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_str(envelope_json).ok()?;
    if v.get("spec").and_then(Value::as_str) != Some(ENVELOPE_SPEC)
        || v.get("enc_alg").and_then(Value::as_str) != Some(ENC_ALG)
    {
        return None;
    }
    let recipients = v.get("recipients")?.as_array()?;
    let kids: Vec<&str> = recipients
        .iter()
        .filter_map(|x| x.get("kid").and_then(Value::as_str))
        .collect();
    let r = recipients
        .iter()
        .find(|x| x.get("kid").and_then(Value::as_str) == Some(kid))?;
    let kem_ct = hex::decode(r.get("kem_ct")?.as_str()?).ok()?;
    let wrap_nonce = hex::decode(r.get("wrap_nonce")?.as_str()?).ok()?;
    let wrapped_cek = hex::decode(r.get("wrapped_cek")?.as_str()?).ok()?;
    let payload_nonce = hex::decode(v.get("payload_nonce")?.as_str()?).ok()?;
    let payload = hex::decode(v.get("payload")?.as_str()?).ok()?;

    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*recipient_seed));
    let ct = Ciphertext::<MlKem1024>::try_from(&kem_ct[..]).ok()?;
    let ss = dk.decapsulate(&ct);
    let cek_vec = gcm_decrypt(&kek(ss.as_slice(), kid), &wrap_nonce, &aad_recipient(kid), &wrapped_cek)?;
    let cek: [u8; 32] = cek_vec.try_into().ok()?;
    gcm_decrypt(&cek, &payload_nonce, &aad_payload(&kids), &payload)
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
    let v: Value = serde_json::from_str(envelope_json).ok()?;
    if v.get("spec").and_then(Value::as_str) != Some(FS_ENVELOPE_SPEC)
        || v.get("enc_alg").and_then(Value::as_str) != Some(FS_ENC_ALG)
    {
        return None;
    }
    let recipients = v.get("recipients")?.as_array()?;
    let rset: Vec<(&str, &str)> = recipients
        .iter()
        .filter_map(|x| {
            Some((
                x.get("kid").and_then(Value::as_str)?,
                x.get("prekey_id").and_then(Value::as_str)?,
            ))
        })
        .collect();
    let r = recipients
        .iter()
        .find(|x| x.get("kid").and_then(Value::as_str) == Some(kid))?;
    let prekey_id = r.get("prekey_id").and_then(Value::as_str)?;
    let ct_ot_bytes = hex::decode(r.get("kem_ct_onetime")?.as_str()?).ok()?;
    let ct_id_bytes = hex::decode(r.get("kem_ct_static")?.as_str()?).ok()?;
    let wrap_nonce = hex::decode(r.get("wrap_nonce")?.as_str()?).ok()?;
    let wrapped_cek = hex::decode(r.get("wrapped_cek")?.as_str()?).ok()?;
    let payload_nonce = hex::decode(v.get("payload_nonce")?.as_str()?).ok()?;
    let payload = hex::decode(v.get("payload")?.as_str()?).ok()?;

    let dk_ot = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*onetime_seed));
    let dk_id = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*static_seed));
    let ct_ot = Ciphertext::<MlKem1024>::try_from(&ct_ot_bytes[..]).ok()?;
    let ct_id = Ciphertext::<MlKem1024>::try_from(&ct_id_bytes[..]).ok()?;
    let ss_ot = dk_ot.decapsulate(&ct_ot);
    let ss_id = dk_id.decapsulate(&ct_id);
    let kek = fs_kek(ss_ot.as_slice(), ss_id.as_slice(), kid, prekey_id);
    let cek_vec = gcm_decrypt(&kek, &wrap_nonce, &aad_recipient_fs(kid, prekey_id), &wrapped_cek)?;
    let cek: [u8; 32] = cek_vec.try_into().ok()?;
    gcm_decrypt(&cek, &payload_nonce, &aad_payload_fs(&rset), &payload)
}
