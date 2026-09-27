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
use sha2::Sha384;

pub const ENVELOPE_SPEC: &str = "sje-envelope/0.1.0";
pub const ENC_ALG: &str = "ML-KEM-1024+HKDF-SHA-384+AES-256-GCM";
const KEK_SALT: &[u8] = b"sje-kek/0.1.0";

fn aad_payload() -> Vec<u8> {
    format!("{ENVELOPE_SPEC}\0{ENC_ALG}").into_bytes()
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
    let payload = gcm_encrypt(cek, payload_nonce, &aad_payload(), plaintext);
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
    let r = v
        .get("recipients")?
        .as_array()?
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
    gcm_decrypt(&cek, &payload_nonce, &aad_payload(), &payload)
}
