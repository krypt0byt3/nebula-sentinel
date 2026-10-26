//! ed25519 signing & verification for GOSSIP envelopes (feature `signing`).
//!
//! The originator signs a **canonical** serialization of the envelope — every
//! field EXCEPT `sig` (can't sign the signature) and `relays` (those are added
//! by relayers after origin-signing, so they must be excluded or every hop would
//! invalidate the origin signature). Receivers reconstruct the same canonical
//! bytes and verify against the origin's public key.
//!
//! Canonicalization: we serialize a stable, field-ordered view to JSON. serde_json
//! preserves struct field order, and we deliberately build a dedicated struct so
//! the signed bytes are independent of map ordering.

use crate::{Envelope, Signature};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature as EdSignature};
use serde::Serialize;

/// Errors from signing/verification.
#[derive(Debug)]
pub enum SignError {
    Serialize(serde_json::Error),
    BadKey(String),
    BadSignature(String),
    NotSigned,
    Verify,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Serialize(e) => write!(f, "canonical serialize failed: {}", e),
            SignError::BadKey(s) => write!(f, "bad key: {}", s),
            SignError::BadSignature(s) => write!(f, "bad signature encoding: {}", s),
            SignError::NotSigned => write!(f, "envelope has no signature"),
            SignError::Verify => write!(f, "signature verification failed"),
        }
    }
}
impl std::error::Error for SignError {}

/// The canonical, signable view of an envelope — excludes `sig` and `relays`.
#[derive(Serialize)]
struct Canonical<'a> {
    schema: &'a str,
    msg_id: &'a str,
    msg_type: String,
    dedup_key: &'a str,
    origin: &'a crate::Origin,
    corroboration: &'a crate::Corroboration,
    confidence: u8,
    severity: crate::Severity,
    ttl_secs: u64,
    created_at: String,
    payload: &'a serde_json::Value,
}

fn canonical_bytes(env: &Envelope) -> Result<Vec<u8>, SignError> {
    let c = Canonical {
        schema: &env.schema,
        msg_id: &env.msg_id,
        msg_type: env.msg_type.as_str().to_string(),
        dedup_key: &env.dedup_key,
        origin: &env.origin,
        corroboration: &env.corroboration,
        confidence: env.confidence,
        severity: env.severity,
        ttl_secs: env.ttl_secs,
        created_at: env.created_at.to_rfc3339(),
        payload: &env.payload,
    };
    serde_json::to_vec(&c).map_err(SignError::Serialize)
}

/// A keypair wrapper for convenience.
pub struct Keypair {
    pub signing: SigningKey,
    pub key_id: String,
}

impl Keypair {
    /// Generate a fresh ed25519 keypair with the given key id.
    pub fn generate(key_id: impl Into<String>) -> Keypair {
        let mut csprng = rand_core::OsRng;
        Keypair { signing: SigningKey::generate(&mut csprng), key_id: key_id.into() }
    }

    /// Load from 32 raw secret-key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32], key_id: impl Into<String>) -> Keypair {
        Keypair { signing: SigningKey::from_bytes(bytes), key_id: key_id.into() }
    }

    /// The public (verifying) key bytes — distribute these to receivers.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Base64 of the public key, for config files / registries.
    pub fn public_b64(&self) -> String {
        b64_encode(&self.public_bytes())
    }
}

/// Sign an envelope in place, setting its `sig` field. Excludes relays/sig from
/// the signed bytes so later relay hops don't invalidate it.
pub fn sign(env: &mut Envelope, kp: &Keypair) -> Result<(), SignError> {
    let bytes = canonical_bytes(env)?;
    let sig: EdSignature = kp.signing.sign(&bytes);
    env.sig = Some(Signature {
        alg: "ed25519".to_string(),
        key_id: kp.key_id.clone(),
        value: b64_encode(&sig.to_bytes()),
    });
    Ok(())
}

/// Verify an envelope's origin signature against a known public key (32 bytes).
pub fn verify(env: &Envelope, public_key: &[u8; 32]) -> Result<(), SignError> {
    let sig = env.sig.as_ref().ok_or(SignError::NotSigned)?;
    let vk = VerifyingKey::from_bytes(public_key).map_err(|e| SignError::BadKey(e.to_string()))?;
    let raw = b64_decode(&sig.value).map_err(|e| SignError::BadSignature(e))?;
    let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| SignError::BadSignature("len != 64".into()))?;
    let ed_sig = EdSignature::from_bytes(&arr);
    let bytes = canonical_bytes(env)?;
    vk.verify(&bytes, &ed_sig).map_err(|_| SignError::Verify)
}

// ── Relay-hop signing ───────────────────────────────────────────────────
// Each relayer signs its own hop record (bound to this message's msg_id), so a
// receiver can trace the path and reject untrusted/forged relay hops. This is
// separate from the origin signature (which excludes `relays`).

/// Canonical bytes a relay hop signs — binds the relayer to this specific
/// message and hop metadata. Excludes the relay's own `sig`.
fn relay_canonical(msg_id: &str, relay: &crate::Relay) -> Vec<u8> {
    format!("gossip-relay|{}|{}|{}|{}",
        msg_id, relay.component.as_str(), relay.id, relay.ts.to_rfc3339()).into_bytes()
}

/// Sign a relay record in place, setting its `sig`.
pub fn sign_relay(msg_id: &str, relay: &mut crate::Relay, kp: &Keypair) {
    let bytes = relay_canonical(msg_id, relay);
    let sig: EdSignature = kp.signing.sign(&bytes);
    relay.sig = Some(b64_encode(&sig.to_bytes()));
}

/// Verify a relay record against the relayer's public key (32 bytes).
pub fn verify_relay(msg_id: &str, relay: &crate::Relay, public_key: &[u8; 32]) -> Result<(), SignError> {
    let sig_b64 = relay.sig.as_ref().ok_or(SignError::NotSigned)?;
    let vk = VerifyingKey::from_bytes(public_key).map_err(|e| SignError::BadKey(e.to_string()))?;
    let raw = b64_decode(sig_b64).map_err(SignError::BadSignature)?;
    let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| SignError::BadSignature("len != 64".into()))?;
    let bytes = relay_canonical(msg_id, relay);
    vk.verify(&bytes, &EdSignature::from_bytes(&arr)).map_err(|_| SignError::Verify)
}

// ── Minimal base64 (no external dep) ────────────────────────────────────
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err("invalid base64 char".into()),
        }
    }
    let clean: Vec<u8> = s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            bits += 6;
        }
        // Left-align remaining bits and emit whole bytes.
        n <<= 24 - bits;
        let bytes = (bits) / 8;
        for i in 0..bytes {
            out.push(((n >> (16 - i * 8)) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, MsgType, Origin};
    use crate::payload::IocPayload;

    fn sample() -> Envelope {
        Envelope::builder(MsgType::IocAlert, Origin::component("nebula-agent", "a1"))
            .payload_ioc(IocPayload::new("sha256", "abcd1234"))
            .build()
    }

    #[test]
    fn sign_then_verify_ok() {
        let kp = Keypair::generate("a1-2026");
        let pk = kp.public_bytes();
        let mut env = sample();
        sign(&mut env, &kp).unwrap();
        assert!(env.sig.is_some());
        verify(&env, &pk).expect("should verify");
    }

    #[test]
    fn tampering_breaks_verification() {
        let kp = Keypair::generate("a1-2026");
        let pk = kp.public_bytes();
        let mut env = sample();
        sign(&mut env, &kp).unwrap();
        env.confidence = 1; // tamper after signing
        assert!(verify(&env, &pk).is_err());
    }

    #[test]
    fn relays_do_not_break_origin_sig() {
        let kp = Keypair::generate("a1-2026");
        let pk = kp.public_bytes();
        let mut env = sample();
        sign(&mut env, &kp).unwrap();
        // A relayer appends a hop — origin signature must still verify.
        env.add_relay(crate::Component::Nexus, "nexus-1", chrono::Utc::now());
        verify(&env, &pk).expect("relay must not invalidate origin signature");
    }

    #[test]
    fn sign_survives_wire_roundtrip() {
        // Mirrors the real path: agent signs, serializes to bytes, sends;
        // Nexus deserializes and verifies. Uses a nested-object payload with a
        // sub-second created_at to catch canonicalization drift.
        let kp = Keypair::generate("a1-2026");
        let pk = kp.public_bytes();
        let mut env = Envelope::builder(MsgType::AtcHealth, Origin::component("nebula-agent", "agent-xyz"))
            .confidence(100)
            .payload_json(serde_json::json!({
                "status": "healthy",
                "cognition": {"llm_available": true, "llm_model": null, "mode": "atc"},
                "collector_backend": "ebpf"
            }))
            .build();
        sign(&mut env, &kp).unwrap();
        let wire = env.to_vec().expect("serialize");
        let received = Envelope::from_slice(&wire).expect("deserialize");
        verify(&received, &pk).expect("must verify after wire round-trip");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"\x00\x01\x02\xfe\xff hello world 12345";
        let e = b64_encode(data);
        let d = b64_decode(&e).unwrap();
        assert_eq!(&d, data);
    }
}
