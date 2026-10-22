use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use thiserror::Error;

use crate::b64;
use crate::canon::canonical_json;
use crate::crypto;
use crate::id::{is_key_id, is_run_id};

pub const TURN_SCHEMA: &str = "gb.turn.v1";
pub const ENVELOPE_TTL_SECONDS: u64 = 300;
pub const ENVELOPE_BUILDER: &str = "eg:cerveau";
const FUTURE_SKEW_SECONDS: i64 = 60;

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("envelope body is not an object")]
    Shape,
    #[error("signing key was rejected")]
    Key,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Schema,
    Version,
    Builder,
    MissingField,
    IntegrityAlg,
    IntegrityKey,
    BodyHash,
    Signature,
    Actor,
    Ttl,
    Clock,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeStatus {
    Fresh(TurnContext),
    Stale(TurnContext),
    Rejected { reason: RejectReason },
}

/// Read-only view of a validated `gb.turn.v1` envelope.
///
/// The envelope is context. It does not override an agent's base rules or the
/// approvals required before a send, a post, or any other side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnContext {
    value: Value,
}

impl TurnContext {
    pub fn schema(&self) -> &str {
        self.str_field("schema").unwrap_or("")
    }
    pub fn envelope_id(&self) -> &str {
        self.str_field("envelope_id").unwrap_or("")
    }
    pub fn run_id(&self) -> &str {
        self.str_field("run_id").unwrap_or("")
    }
    pub fn generated_at(&self) -> &str {
        self.str_field("generated_at").unwrap_or("")
    }
    pub fn expires_at(&self) -> &str {
        self.str_field("expires_at").unwrap_or("")
    }
    pub fn ttl_seconds(&self) -> u64 {
        self.value
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }
    pub fn actor(&self) -> Option<&str> {
        self.value.pointer("/agent/actor").and_then(Value::as_str)
    }
    pub fn goal(&self) -> Option<&str> {
        self.str_field("goal")
    }
    pub fn get(&self, pointer: &str) -> Option<&Value> {
        self.value.pointer(pointer)
    }
    /// Detached JSON copy. Mutating the copy does not change this context.
    pub fn snapshot(&self) -> Value {
        self.value.clone()
    }

    fn str_field(&self, name: &str) -> Option<&str> {
        self.value.get(name).and_then(Value::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct VerifyConfig {
    pub signing_key_id: String,
    pub signing_public: [u8; 32],
    pub expected_actor: Option<String>,
}

pub fn attach_integrity(
    body: &Value,
    key_id: &str,
    signing_seed: &[u8; 32],
) -> Result<Value, EnvelopeError> {
    if !is_key_id(key_id) {
        return Err(EnvelopeError::Key);
    }
    let mut unsigned = body.clone();
    let object = unsigned.as_object_mut().ok_or(EnvelopeError::Shape)?;
    object.remove("integrity");
    let digest = crypto::sha256(canonical_json(&unsigned).as_bytes());
    let signature = SigningKey::from_bytes(signing_seed).sign(&digest);
    unsigned["integrity"] = json!({
        "alg": "ed25519",
        "key_id": key_id,
        "body_sha256": hex::encode(digest),
        "signature": b64::encode(&signature.to_bytes()),
    });
    Ok(unsigned)
}

pub fn validate_envelope(value: &Value, cfg: &VerifyConfig, now: DateTime<Utc>) -> EnvelopeStatus {
    let Some(object) = value.as_object() else {
        return reject(RejectReason::Malformed);
    };
    if object.get("schema").and_then(Value::as_str) != Some(TURN_SCHEMA) {
        return reject(RejectReason::Schema);
    }
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return reject(RejectReason::Version);
    }
    if object.get("builder").and_then(Value::as_str) != Some(ENVELOPE_BUILDER) {
        return reject(RejectReason::Builder);
    }
    for field in ["envelope_id", "run_id", "generated_at", "expires_at"] {
        if object.get(field).and_then(Value::as_str).is_none() {
            return reject(RejectReason::MissingField);
        }
    }
    let run_id = object["run_id"].as_str().unwrap_or("");
    if !is_run_id(run_id) {
        return reject(RejectReason::Malformed);
    }
    let actor = value.pointer("/agent/actor").and_then(Value::as_str);
    let Some(actor) = actor else {
        return reject(RejectReason::MissingField);
    };
    let integrity = match object.get("integrity").and_then(Value::as_object) {
        Some(v) => v,
        None => return reject(RejectReason::MissingField),
    };
    if integrity.get("alg").and_then(Value::as_str) != Some("ed25519") {
        return reject(RejectReason::IntegrityAlg);
    }
    let key_id = match integrity.get("key_id").and_then(Value::as_str) {
        Some(v) if is_key_id(v) => v,
        Some(_) => return reject(RejectReason::Malformed),
        None => return reject(RejectReason::MissingField),
    };
    if key_id != cfg.signing_key_id {
        return reject(RejectReason::IntegrityKey);
    }
    let claimed_hash = match integrity.get("body_sha256").and_then(Value::as_str) {
        Some(v) => v,
        None => return reject(RejectReason::MissingField),
    };
    let claimed_sig = match integrity.get("signature").and_then(Value::as_str) {
        Some(v) => v,
        None => return reject(RejectReason::MissingField),
    };

    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .expect("object")
        .remove("integrity");
    let digest = crypto::sha256(canonical_json(&unsigned).as_bytes());
    if !claimed_hash.eq_ignore_ascii_case(&hex::encode(digest)) {
        return reject(RejectReason::BodyHash);
    }
    let Ok(vk) = VerifyingKey::from_bytes(&cfg.signing_public) else {
        return reject(RejectReason::Signature);
    };
    let Ok(sig_bytes) = b64::decode(claimed_sig) else {
        return reject(RejectReason::Signature);
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return reject(RejectReason::Signature);
    };
    if vk.verify(&digest, &signature).is_err() {
        return reject(RejectReason::Signature);
    }
    if cfg
        .expected_actor
        .as_deref()
        .is_some_and(|want| want != actor)
    {
        return reject(RejectReason::Actor);
    }

    let ttl = match object.get("ttl_seconds").and_then(Value::as_u64) {
        Some(v) => v,
        None => return reject(RejectReason::Ttl),
    };
    if ttl != ENVELOPE_TTL_SECONDS {
        return reject(RejectReason::Ttl);
    }
    let generated = match parse_time(object["generated_at"].as_str().unwrap_or("")) {
        Some(v) => v,
        None => return reject(RejectReason::Clock),
    };
    let expires = match parse_time(object["expires_at"].as_str().unwrap_or("")) {
        Some(v) => v,
        None => return reject(RejectReason::Clock),
    };
    if expires != generated + Duration::seconds(ENVELOPE_TTL_SECONDS as i64) {
        return reject(RejectReason::Ttl);
    }
    let ctx = TurnContext {
        value: value.clone(),
    };
    if generated > now + Duration::seconds(FUTURE_SKEW_SECONDS) {
        return reject(RejectReason::Clock);
    }
    if now >= expires {
        EnvelopeStatus::Stale(ctx)
    } else {
        EnvelopeStatus::Fresh(ctx)
    }
}

fn reject(reason: RejectReason) -> EnvelopeStatus {
    EnvelopeStatus::Rejected { reason }
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub fn sample_envelope(
    run_id: &str,
    actor: &str,
    signing_seed: &[u8; 32],
    signing_key_id: &str,
    generated_at: &str,
) -> Result<Value, EnvelopeError> {
    let generated = parse_time(generated_at).ok_or(EnvelopeError::Shape)?;
    let expires = generated + Duration::seconds(ENVELOPE_TTL_SECONDS as i64);
    let body = json!({
        "schema": TURN_SCHEMA,
        "envelope_id": format!("env_{run_id}"),
        "version": 1,
        "run_id": run_id,
        "generated_at": generated_at,
        "ttl_seconds": ENVELOPE_TTL_SECONDS,
        "expires_at": expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "builder": ENVELOPE_BUILDER,
        "agent": {"actor": actor},
    });
    attach_integrity(&body, signing_key_id, signing_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        [4u8; 32]
    }

    fn cfg() -> VerifyConfig {
        let signing = SigningKey::from_bytes(&seed());
        VerifyConfig {
            signing_key_id: "cerveau-test".into(),
            signing_public: signing.verifying_key().to_bytes(),
            expected_actor: Some("gb:agent-test".into()),
        }
    }

    fn envelope() -> Value {
        sample_envelope(
            "run_TEST",
            "gb:agent-test",
            &seed(),
            "cerveau-test",
            "2026-10-22T15:45:00Z",
        )
        .unwrap()
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn fresh_stale_and_rejections() {
        let env = envelope();
        match validate_envelope(&env, &cfg(), at("2026-10-22T15:45:30Z")) {
            EnvelopeStatus::Fresh(ctx) => {
                assert_eq!(ctx.run_id(), "run_TEST");
                assert_eq!(ctx.actor(), Some("gb:agent-test"));
                assert_eq!(ctx.ttl_seconds(), 300);
                let mut snap = ctx.snapshot();
                snap["goal"] = json!("hacked");
                assert_eq!(ctx.goal(), None);
            }
            other => panic!("expected fresh, got {other:?}"),
        }
        assert!(matches!(
            validate_envelope(&env, &cfg(), at("2026-10-22T15:50:00Z")),
            EnvelopeStatus::Stale(_)
        ));
        let mut bad = env.clone();
        bad["ttl_seconds"] = json!(299);
        // signature no longer matches
        assert!(matches!(
            validate_envelope(&bad, &cfg(), at("2026-10-22T15:45:30Z")),
            EnvelopeStatus::Rejected {
                reason: RejectReason::BodyHash
            }
        ));
        let mut skew = env.clone();
        assert!(matches!(
            validate_envelope(&skew, &cfg(), at("2026-10-22T15:40:00Z")),
            EnvelopeStatus::Rejected {
                reason: RejectReason::Clock
            }
        ));
        skew["agent"]["actor"] = json!("gb:other");
        assert!(matches!(
            validate_envelope(&skew, &cfg(), at("2026-10-22T15:45:30Z")),
            EnvelopeStatus::Rejected {
                reason: RejectReason::BodyHash
            } | EnvelopeStatus::Rejected {
                reason: RejectReason::Signature
            } | EnvelopeStatus::Rejected {
                reason: RejectReason::Actor
            }
        ));
        let mut tampered = env.clone();
        let sig = tampered["integrity"]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let mut chars: Vec<u8> = sig.into_bytes();
        chars[0] = if chars[0] == b'A' { b'B' } else { b'A' };
        tampered["integrity"]["signature"] = json!(String::from_utf8(chars).unwrap());
        assert!(matches!(
            validate_envelope(&tampered, &cfg(), at("2026-10-22T15:45:30Z")),
            EnvelopeStatus::Rejected {
                reason: RejectReason::Signature
            }
        ));
    }
}
