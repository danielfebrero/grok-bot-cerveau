use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::b64;
use crate::body::RunBody;
use crate::canon::canonical_json;
use crate::crypto::{self, aead_open, aead_seal, hkdf_sha256};
use crate::id::{self, is_key_id, is_run_id};
use crate::key::AgentKey;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

pub const RUN_SCHEMA: &str = "gb.run.v1";
pub const SEAL_ALG: &str = "x25519-hkdf-sha256-chacha20poly1305";
pub const SIGN_ALG: &str = "ed25519";

/// Test or vector randomness. Production sealing draws both from the OS RNG.
#[derive(Debug, Clone)]
pub struct SealRandomness {
    pub ephemeral_secret: [u8; 32],
    pub nonce: [u8; 12],
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("invalid identifier: {0}")]
    Id(&'static str),
    #[error("diffie-hellman was not contributory")]
    Dh,
    #[error("crypto failure")]
    Crypto,
    #[error("signature mismatch")]
    Signature,
    #[error("ciphertext could not be opened")]
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRef {
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncBlock {
    pub alg: String,
    pub recipient_key_id: String,
    pub epk: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigBlock {
    pub alg: String,
    pub signed: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMessage {
    pub schema: String,
    pub run_id: String,
    pub seq: u64,
    pub sent_at: String,
    pub replay: bool,
    pub agent: AgentRef,
    pub key_id: String,
    pub enc: EncBlock,
    pub sig: SigBlock,
}

pub struct SealRequest<'a> {
    pub body: &'a RunBody,
    pub run_id: &'a str,
    pub seq: u64,
    pub sent_at: &'a str,
    pub replay: bool,
    pub agent: &'a AgentKey,
    pub recipient_key_id: &'a str,
    pub recipient_public: &'a [u8; 32],
    pub randomness: Option<&'a SealRandomness>,
}

pub fn signature_preimage(
    schema: &str,
    run_id: &str,
    seq: u64,
    sent_at: &str,
    key_id: &str,
    ciphertext_b64: &str,
) -> String {
    format!("{schema}|{run_id}|{seq}|{sent_at}|{key_id}|{ciphertext_b64}")
}

pub fn associated_data(
    run_id: &str,
    seq: u64,
    sent_at: &str,
    key_id: &str,
    actor: &str,
    recipient_key_id: &str,
) -> String {
    format!(
        "gb.run.v1\nrun_id={run_id}\nseq={seq}\nsent_at={sent_at}\nkey_id={key_id}\nactor={actor}\nrecipient_key_id={recipient_key_id}\n"
    )
}

pub fn hkdf_info(recipient_key_id: &str, sender_key_id: &str) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"gb.run.v1/x25519-hkdf-sha256-chacha20poly1305\x00");
    info.extend_from_slice(recipient_key_id.as_bytes());
    info.extend_from_slice(b"\x00");
    info.extend_from_slice(sender_key_id.as_bytes());
    info
}

pub fn hkdf_salt(epk: &[u8; 32], sender_x25519: &[u8; 32], recipient: &[u8; 32]) -> [u8; 96] {
    let mut salt = [0u8; 96];
    salt[..32].copy_from_slice(epk);
    salt[32..64].copy_from_slice(sender_x25519);
    salt[64..].copy_from_slice(recipient);
    salt
}

pub fn seal_run(req: SealRequest<'_>) -> Result<RunMessage, SealError> {
    if !is_run_id(req.run_id) {
        return Err(SealError::Id("run_id"));
    }
    if !is_key_id(req.agent.key_id()) || !is_key_id(req.recipient_key_id) {
        return Err(SealError::Id("key_id"));
    }
    if req.seq == 0 {
        return Err(SealError::Id("seq"));
    }
    if !id::is_sent_at(req.sent_at) {
        return Err(SealError::Id("sent_at"));
    }
    if !id::is_safe_actor(req.agent.actor()) {
        return Err(SealError::Id("actor"));
    }

    let plaintext = canonical_json(&serde_json::to_value(req.body).map_err(|_| SealError::Crypto)?);
    let mut eph_secret = [0u8; 32];
    let mut nonce = [0u8; 12];
    if let Some(random) = req.randomness {
        eph_secret.copy_from_slice(&random.ephemeral_secret);
        nonce.copy_from_slice(&random.nonce);
    } else {
        OsRng.fill_bytes(&mut eph_secret);
        OsRng.fill_bytes(&mut nonce);
    }
    let eph_secret = Zeroizing::new(eph_secret);
    let epk = crypto::x25519_public(&eph_secret);
    let agent_scalar = Zeroizing::new(crypto::ed25519_seed_to_x25519_secret(req.agent.seed()));
    let eph_shared = crypto::dh(&eph_secret, req.recipient_public).map_err(|_| SealError::Dh)?;
    let static_shared =
        crypto::dh(&agent_scalar, req.recipient_public).map_err(|_| SealError::Dh)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&eph_shared);
    ikm[32..].copy_from_slice(&static_shared);
    let salt = hkdf_salt(&epk, req.agent.x25519_public(), req.recipient_public);
    let info = hkdf_info(req.recipient_key_id, req.agent.key_id());
    let mut key = hkdf_sha256(&salt, ikm.as_slice(), &info).map_err(|_| SealError::Crypto)?;
    let aad = associated_data(
        req.run_id,
        req.seq,
        req.sent_at,
        req.agent.key_id(),
        req.agent.actor(),
        req.recipient_key_id,
    );
    let ciphertext = aead_seal(&key, &nonce, aad.as_bytes(), plaintext.as_bytes())
        .map_err(|_| SealError::Crypto)?;
    crypto::zeroize_key(&mut key);
    let ciphertext_b64 = b64::encode(&ciphertext);
    let preimage = signature_preimage(
        RUN_SCHEMA,
        req.run_id,
        req.seq,
        req.sent_at,
        req.agent.key_id(),
        &ciphertext_b64,
    );
    let digest = crypto::sha256(preimage.as_bytes());
    let signature = req.agent.signing_key().sign(&digest);

    Ok(RunMessage {
        schema: RUN_SCHEMA.to_string(),
        run_id: req.run_id.to_string(),
        seq: req.seq,
        sent_at: req.sent_at.to_string(),
        replay: req.replay,
        agent: AgentRef {
            actor: req.agent.actor().to_string(),
        },
        key_id: req.agent.key_id().to_string(),
        enc: EncBlock {
            alg: SEAL_ALG.to_string(),
            recipient_key_id: req.recipient_key_id.to_string(),
            epk: b64::encode(&epk),
            nonce: b64::encode(&nonce),
            ciphertext: ciphertext_b64,
        },
        sig: SigBlock {
            alg: SIGN_ALG.to_string(),
            signed: hex::encode(digest),
            value: b64::encode(&signature.to_bytes()),
        },
    })
}

pub fn open_run(
    message: &RunMessage,
    recipient_secret: &[u8; 32],
    sender_ed25519_public: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    if message.schema != RUN_SCHEMA || message.enc.alg != SEAL_ALG || message.sig.alg != SIGN_ALG {
        return Err(SealError::Open);
    }
    if !is_run_id(&message.run_id)
        || !is_key_id(&message.key_id)
        || !is_key_id(&message.enc.recipient_key_id)
    {
        return Err(SealError::Id("run_id"));
    }
    let preimage = signature_preimage(
        &message.schema,
        &message.run_id,
        message.seq,
        &message.sent_at,
        &message.key_id,
        &message.enc.ciphertext,
    );
    let digest = crypto::sha256(preimage.as_bytes());
    if !eq_hex(&message.sig.signed, &digest) {
        return Err(SealError::Signature);
    }
    let vk = VerifyingKey::from_bytes(sender_ed25519_public).map_err(|_| SealError::Signature)?;
    let sig_bytes = b64::decode(&message.sig.value).map_err(|_| SealError::Signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| SealError::Signature)?;
    vk.verify(&digest, &signature)
        .map_err(|_| SealError::Signature)?;

    let epk: [u8; 32] = b64::decode_array(&message.enc.epk).map_err(|_| SealError::Open)?;
    let nonce = b64::decode(&message.enc.nonce).map_err(|_| SealError::Open)?;
    let ciphertext = b64::decode(&message.enc.ciphertext).map_err(|_| SealError::Open)?;
    let sender_x =
        crypto::ed25519_public_to_x25519(sender_ed25519_public).map_err(|_| SealError::Open)?;
    let eph_shared = crypto::dh(recipient_secret, &epk).map_err(|_| SealError::Dh)?;
    let static_shared = crypto::dh(recipient_secret, &sender_x).map_err(|_| SealError::Dh)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&eph_shared);
    ikm[32..].copy_from_slice(&static_shared);
    let recipient_public = crypto::x25519_public(recipient_secret);
    let salt = hkdf_salt(&epk, &sender_x, &recipient_public);
    let info = hkdf_info(&message.enc.recipient_key_id, &message.key_id);
    let mut key = hkdf_sha256(&salt, ikm.as_slice(), &info).map_err(|_| SealError::Crypto)?;
    let aad = associated_data(
        &message.run_id,
        message.seq,
        &message.sent_at,
        &message.key_id,
        &message.agent.actor,
        &message.enc.recipient_key_id,
    );
    let plain =
        aead_open(&key, &nonce, aad.as_bytes(), &ciphertext).map_err(|_| SealError::Open)?;
    crypto::zeroize_key(&mut key);
    Ok(plain)
}

fn eq_hex(claimed: &str, digest: &[u8; 32]) -> bool {
    claimed.eq_ignore_ascii_case(&hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::{prepare_body, MessageOrigin, RunInput, TurnMessage};
    use crate::key::AgentKey;
    use chrono::{DateTime, Utc};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn agent() -> AgentKey {
        AgentKey::from_seed(
            "agent-test",
            [9u8; 32],
            DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    fn body() -> crate::body::RunBody {
        prepare_body(RunInput {
            transcript: "voir 0123456789abcdef0123456789abcdef01234567 merci".into(),
            messages: vec![TurnMessage {
                origin: MessageOrigin::Human {
                    from: "dani".into(),
                },
                text: "bonjour".into(),
                ref_id: None,
                at: None,
            }],
            ..RunInput::default()
        })
        .unwrap()
    }

    #[test]
    fn roundtrip_survives_replay_flip_and_rejects_bad_ids() {
        let agent = agent();
        let recip = StaticSecret::random_from_rng(OsRng);
        let recip_pub = PublicKey::from(&recip).to_bytes();
        let recip_sec = recip.to_bytes();
        let message = seal_run(SealRequest {
            body: &body(),
            run_id: "run_TEST",
            seq: 3,
            sent_at: "2026-10-22T15:44:58Z",
            replay: false,
            agent: &agent,
            recipient_key_id: "cerveau-test",
            recipient_public: &recip_pub,
            randomness: None,
        })
        .unwrap();
        assert!(is_run_id(&message.run_id));
        assert!(is_key_id(&message.key_id));
        let plain = open_run(&message, &recip_sec, agent.ed25519_public()).unwrap();
        let text = String::from_utf8(plain).unwrap();
        assert!(text.contains("voir "));
        assert!(text.contains("[REDACTED:hex]"));
        assert!(text.contains("\"from\":\"dani\""));
        assert!(!text.contains("0123456789abcdef0123456789abcdef01234567"));

        let mut replayed = message.clone();
        replayed.replay = true;
        let again = open_run(&replayed, &recip_sec, agent.ed25519_public()).unwrap();
        assert_eq!(again, text.as_bytes());

        let mut bad_actor = message.clone();
        bad_actor.agent.actor = "gb:other".into();
        assert!(open_run(&bad_actor, &recip_sec, agent.ed25519_public()).is_err());

        let body = body();
        let long = "r".repeat(81);
        for (run_id, recipient_key_id) in [
            ("run id", "cerveau-test"),
            (long.as_str(), "cerveau-test"),
            ("run_OK", "cerveau.test"),
            ("run/bad", "cerveau-test"),
        ] {
            let err = seal_run(SealRequest {
                body: &body,
                run_id,
                seq: 3,
                sent_at: "2026-10-22T15:44:58Z",
                replay: false,
                agent: &agent,
                recipient_key_id,
                recipient_public: &recip_pub,
                randomness: None,
            });
            assert!(err.is_err(), "{run_id} {recipient_key_id}");
        }
    }

    /// Public interop vector. The seeds are SHA-256 of a fixed label, not secrets.
    #[test]
    fn public_vector_is_stable() {
        let agent_seed = vector_seed("agent");
        let recipient_seed = vector_seed("recipient");
        let ephemeral = vector_seed("ephemeral");
        let nonce_hash = vector_seed("nonce");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_hash[..12]);
        let created = DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let agent = AgentKey::from_seed("agent-test", agent_seed, created).unwrap();
        let recipient_secret = crate::crypto::ed25519_seed_to_x25519_secret(&recipient_seed);
        let recipient_public = crate::crypto::x25519_public(&recipient_secret);
        let body = vector_body();
        let message = seal_run(SealRequest {
            body: &body,
            run_id: "run_VECTOR",
            seq: 7,
            sent_at: "2026-10-22T15:44:58Z",
            replay: false,
            agent: &agent,
            recipient_key_id: "cerveau-test",
            recipient_public: &recipient_public,
            randomness: Some(&SealRandomness {
                ephemeral_secret: ephemeral,
                nonce,
            }),
        })
        .unwrap();
        let plain = open_run(&message, &recipient_secret, agent.ed25519_public()).unwrap();
        let mut replayed = message.clone();
        replayed.replay = true;
        assert_eq!(
            open_run(&replayed, &recipient_secret, agent.ed25519_public()).unwrap(),
            plain
        );
        assert_eq!(replayed.sig, message.sig);

        let fixture = serde_json::json!({
            "note": "Public test vector. These keys are fixtures derived from public labels, not secrets.",
            "domain": "SHA-256(\"cerveau-public-test-vector-v1\\0\" || label)",
            "labels": {
                "agent": "ed25519 seed",
                "recipient": "ed25519 seed, then libsodium/RFC 8032 SHA-512 clamp to the X25519 scalar",
                "ephemeral": "unclamped X25519 ephemeral secret (the seal clamps it)",
                "nonce": "first 12 bytes are the ChaCha20-Poly1305 nonce"
            },
            "agent_seed_hex": hex::encode(agent_seed),
            "recipient_seed_hex": hex::encode(recipient_seed),
            "ephemeral_hex": hex::encode(ephemeral),
            "nonce_hex": hex::encode(nonce),
            "agent_ed25519_public_b64": b64::encode(agent.ed25519_public()),
            "agent_x25519_public_b64": b64::encode(agent.x25519_public()),
            "recipient_x25519_public_b64": b64::encode(&recipient_public),
            "plaintext": String::from_utf8(plain).unwrap(),
            "message": message,
        });
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/gb_run_v1.json");
        if std::env::var_os("WRITE_VECTORS").is_some_and(|v| v == "1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut bytes = serde_json::to_vec_pretty(&fixture).unwrap();
            bytes.push(b'\n');
            std::fs::write(&path, bytes).unwrap();
        }
        let stored: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("tests/fixtures/gb_run_v1.json"),
        )
        .unwrap();
        assert_eq!(stored, fixture);
    }

    fn vector_seed(label: &str) -> [u8; 32] {
        let mut material = b"cerveau-public-test-vector-v1\0".to_vec();
        material.extend_from_slice(label.as_bytes());
        crate::crypto::sha256(&material)
    }

    fn vector_body() -> crate::body::RunBody {
        let human = TurnMessage {
            origin: MessageOrigin::Human {
                from: "Dani".into(),
            },
            text: "bonjour".into(),
            ref_id: None,
            at: Some("2026-10-22T15:44:58Z".into()),
        };
        prepare_body(RunInput {
            transcript: "commit 0123456789abcdef0123456789abcdef01234567 ok".into(),
            trigger: Some(human.clone()),
            messages: vec![
                human,
                TurnMessage {
                    origin: MessageOrigin::RelayedAgent {
                        from: "gb:other".into(),
                    },
                    text: "relai".into(),
                    ref_id: None,
                    at: None,
                },
                TurnMessage {
                    origin: MessageOrigin::Inbound {
                        from: "x:mention".into(),
                    },
                    text: "externe".into(),
                    ref_id: None,
                    at: None,
                },
                TurnMessage {
                    origin: MessageOrigin::Tool {
                        from: "shell".into(),
                    },
                    text: "ok".into(),
                    ref_id: None,
                    at: None,
                },
            ],
            ..RunInput::default()
        })
        .unwrap()
    }
}
