use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::b64;
use crate::crypto::{ed25519_seed_to_x25519_secret, x25519_public};
use crate::id::{self, is_agent_id, is_key_id, AGENT_ID_MAX};
use crate::util::{self, ensure_private};

pub const KEY_SCHEMA: &str = "gb.agent_key.v1";
pub const PUB_SCHEMA: &str = "gb.agent_pub.v1";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("agent id must be 1..={AGENT_ID_MAX} bytes of [A-Za-z0-9._:-]")]
    AgentId,
    #[error("key id is not an ASCII token of [A-Za-z0-9_-]")]
    KeyId,
    #[error("agent key already exists")]
    AlreadyExists,
    #[error("refusing to replace a key while an encrypted queue is present")]
    QueuePresent,
    #[error("agent key not found")]
    NotFound,
    #[error("agent key file does not match the requested agent")]
    AgentMismatch,
    #[error("agent key file is inconsistent")]
    Corrupt,
    #[error("agent key permissions are too open")]
    Permissions,
    #[error("home directory is not set")]
    Home,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Ed25519 agent key. The seed is never printed by `Debug`.
pub struct AgentKey {
    seed: Zeroizing<[u8; 32]>,
    agent_id: String,
    actor: String,
    key_id: String,
    ed25519_public: [u8; 32],
    x25519_public: [u8; 32],
    created_at: String,
}

impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("agent_id", &self.agent_id)
            .field("actor", &self.actor)
            .field("key_id", &self.key_id)
            .field("ed25519_public", &b64::encode(&self.ed25519_public))
            .field("seed", &"[redacted]")
            .finish()
    }
}

impl AgentKey {
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_public
    }
    pub fn x25519_public(&self) -> &[u8; 32] {
        &self.x25519_public
    }
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
    pub fn public_export(&self) -> PublicExport {
        PublicExport {
            schema: PUB_SCHEMA.to_string(),
            agent_id: self.agent_id.clone(),
            actor: self.actor.clone(),
            key_id: self.key_id.clone(),
            ed25519_public_key: b64::encode(&self.ed25519_public),
            x25519_public_key: b64::encode(&self.x25519_public),
            alg_sign: "ed25519".to_string(),
            alg_enc: "x25519".to_string(),
            created_at: self.created_at.clone(),
        }
    }

    /// Rebuilds a key from its 32-byte ed25519 seed. The seed is the private key.
    pub fn from_seed(
        agent_id: impl Into<String>,
        mut seed: [u8; 32],
        created_at: DateTime<Utc>,
    ) -> Result<Self, KeyError> {
        let agent_id = agent_id.into();
        let built = assemble(&agent_id, &seed, created_at);
        seed.zeroize();
        built
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicExport {
    pub schema: String,
    pub agent_id: String,
    pub actor: String,
    pub key_id: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    pub alg_sign: String,
    pub alg_enc: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    schema: String,
    agent_id: String,
    actor: String,
    key_id: String,
    created_at: String,
    ed25519_seed: String,
    ed25519_public: String,
    x25519_public: String,
}

pub fn default_home() -> Result<PathBuf, KeyError> {
    if let Ok(dir) = std::env::var("CERVEAU_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("cerveau"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| KeyError::Home)?;
    Ok(PathBuf::from(home).join(".local/share/cerveau"))
}

pub fn agent_dir(home: &Path, agent_id: &str) -> Result<PathBuf, KeyError> {
    if !is_agent_id(agent_id) {
        return Err(KeyError::AgentId);
    }
    Ok(home.join("agents").join(dir_component(agent_id)?))
}

pub fn generate_agent_key(
    home: &Path,
    agent_id: &str,
    force: bool,
) -> Result<PublicExport, KeyError> {
    if !is_agent_id(agent_id) {
        return Err(KeyError::AgentId);
    }
    let dir = agent_dir(home, agent_id)?;
    util::ensure_dir(&dir)?;
    let path = dir.join("key.json");
    let queue = dir.join("queue.q");
    if path.exists() && !force {
        return Err(KeyError::AlreadyExists);
    }
    if force && queue.exists() {
        return Err(KeyError::QueuePresent);
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let created = Utc::now();
    let key = AgentKey::from_seed(agent_id, seed, created)?;
    write_key(&dir, &key)?;
    Ok(key.public_export())
}

pub fn load_agent_key(home: &Path, agent_id: &str) -> Result<AgentKey, KeyError> {
    let dir = agent_dir(home, agent_id)?;
    let path = dir.join("key.json");
    if !path.exists() {
        return Err(KeyError::NotFound);
    }
    ensure_private(&path).map_err(|_| KeyError::Permissions)?;
    let mut bytes = fs::read(&path)?;
    let parsed: Result<KeyFile, _> = serde_json::from_slice(&bytes);
    bytes.zeroize();
    let file = parsed.map_err(|_| KeyError::Corrupt)?;
    if file.schema != KEY_SCHEMA || file.agent_id != agent_id {
        return Err(KeyError::AgentMismatch);
    }
    if !is_key_id(&file.key_id) {
        return Err(KeyError::KeyId);
    }
    let created = DateTime::parse_from_rfc3339(&file.created_at)
        .map_err(|_| KeyError::Corrupt)?
        .with_timezone(&Utc);
    let seed: [u8; 32] =
        b64::decode_array(file.ed25519_seed.trim()).map_err(|_| KeyError::Corrupt)?;
    let key = AgentKey::from_seed(agent_id, seed, created)?;
    if key.key_id != file.key_id
        || key.actor != file.actor
        || b64::encode(key.ed25519_public()) != file.ed25519_public
        || b64::encode(key.x25519_public()) != file.x25519_public
    {
        return Err(KeyError::Corrupt);
    }
    Ok(key)
}

fn write_key(dir: &Path, key: &AgentKey) -> Result<(), KeyError> {
    let file = KeyFile {
        schema: KEY_SCHEMA.to_string(),
        agent_id: key.agent_id.clone(),
        actor: key.actor.clone(),
        key_id: key.key_id.clone(),
        created_at: key.created_at.clone(),
        ed25519_seed: b64::encode(key.seed()),
        ed25519_public: b64::encode(key.ed25519_public()),
        x25519_public: b64::encode(key.x25519_public()),
    };
    let mut bytes = serde_json::to_vec_pretty(&file).map_err(|_| KeyError::Corrupt)?;
    bytes.push(b'\n');
    util::write_durable(dir, "key.json", &bytes)?;
    bytes.zeroize();
    Ok(())
}

fn assemble(
    agent_id: &str,
    seed: &[u8; 32],
    created_at: DateTime<Utc>,
) -> Result<AgentKey, KeyError> {
    if !is_agent_id(agent_id) {
        return Err(KeyError::AgentId);
    }
    let signing = SigningKey::from_bytes(seed);
    let ed25519_public = signing.verifying_key().to_bytes();
    let x_secret = ed25519_seed_to_x25519_secret(seed);
    let x25519_public = x25519_public(&x_secret);
    let actor = actor_for(agent_id);
    let key_id = key_id_for(agent_id, created_at)?;
    if !id::is_safe_actor(&actor) {
        return Err(KeyError::AgentId);
    }
    Ok(AgentKey {
        seed: Zeroizing::new(*seed),
        agent_id: agent_id.to_string(),
        actor,
        key_id,
        ed25519_public,
        x25519_public,
        created_at: created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub(crate) fn actor_for(agent_id: &str) -> String {
    if let Some(rest) = agent_id.strip_prefix("gb:") {
        format!("gb:{rest}")
    } else {
        format!("gb:{agent_id}")
    }
}

pub(crate) fn key_id_for(agent_id: &str, created: DateTime<Utc>) -> Result<String, KeyError> {
    let bare = agent_id.strip_prefix("gb:").unwrap_or(agent_id);
    let mut safe = String::new();
    for c in bare.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            safe.push(c);
        } else {
            safe.push('_');
        }
    }
    let safe = safe.trim_matches('_').to_string();
    if safe.is_empty() {
        return Err(KeyError::AgentId);
    }
    let key_id = format!("gb-{safe}-{}", created.format("%Y%m"));
    if !is_key_id(&key_id) {
        return Err(KeyError::KeyId);
    }
    Ok(key_id)
}

pub(crate) fn dir_component(agent_id: &str) -> Result<String, KeyError> {
    let bare = agent_id.strip_prefix("gb:").unwrap_or(agent_id);
    let mut safe = String::new();
    for c in bare.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            safe.push(c);
        } else {
            safe.push('_');
        }
    }
    let safe = safe.trim_matches('_').to_string();
    if safe.is_empty() || safe == "." || safe == ".." {
        return Err(KeyError::AgentId);
    }
    Ok(safe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use std::os::unix::fs::PermissionsExt;

    fn scratch() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cerveau-key-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn keygen_is_private_and_debug_hides_the_seed() {
        let home = scratch();
        let export = generate_agent_key(&home, "agent-test", false).unwrap();
        assert!(is_key_id(&export.key_id));
        assert!(!export.key_id.contains(':'));
        assert!(!export.key_id.contains('.'));
        assert_eq!(export.actor, "gb:agent-test");
        let ym = Utc::now().format("%Y%m").to_string();
        assert!(export.key_id.ends_with(&ym));
        let path = agent_dir(&home, "agent-test").unwrap().join("key.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let raw = fs::read_to_string(&path).unwrap();
        let key = load_agent_key(&home, "agent-test").unwrap();
        let debug = format!("{key:?}");
        let seed_b64 = {
            let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
            file["ed25519_seed"].as_str().unwrap().to_string()
        };
        assert!(!debug.contains(&seed_b64));
        assert!(debug.contains("[redacted]"));
        let stdout = serde_json::to_string(&export).unwrap();
        assert!(!stdout.contains(&seed_b64));
        assert!(generate_agent_key(&home, "agent-test", false).is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn open_permissions_and_bad_key_id_are_refused() {
        let home = scratch();
        generate_agent_key(&home, "agent-test", false).unwrap();
        let path = agent_dir(&home, "agent-test").unwrap().join("key.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_agent_key(&home, "agent-test"),
            Err(KeyError::Permissions)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value["key_id"] = serde_json::Value::String("not a key".into());
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_agent_key(&home, "agent-test").is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn x25519_public_matches_edwards_conversion() {
        let key = AgentKey::from_seed(
            "agent-test",
            [7u8; 32],
            DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let converted = crypto::ed25519_public_to_x25519(key.ed25519_public()).unwrap();
        assert_eq!(converted, *key.x25519_public());
        assert_eq!(key.key_id(), "gb-agent-test-202610");
    }
}
