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
use crate::id::{self, is_agent_id, is_key_id, is_tenant_id, AGENT_ID_MAX};
use crate::queue::{QueueState, QueueStore};
use crate::util::{self, ensure_private};

pub const KEY_SCHEMA: &str = "gb.agent_key.v1";
pub const PUB_SCHEMA: &str = "gb.agent_pub.v1";
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_RETIRED: &str = "retired";
pub const STATUS_REVOKED: &str = "revoked";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("agent id must be 1..={AGENT_ID_MAX} bytes of [A-Za-z0-9._:-]")]
    AgentId,
    #[error("tenant id is not an ASCII token of [A-Za-z0-9_-]")]
    Tenant,
    #[error("key id is not an ASCII token of [A-Za-z0-9_-]")]
    KeyId,
    #[error("agent key already exists")]
    AlreadyExists,
    #[error("agent key not found")]
    NotFound,
    #[error("agent key file does not match the requested agent")]
    AgentMismatch,
    #[error("agent key file is inconsistent")]
    Corrupt,
    #[error("agent key permissions are too open")]
    Permissions,
    #[error("this key is retired or revoked; rotate to a new active key")]
    Retired,
    #[error("home directory is not set")]
    Home,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("queue: {0}")]
    Queue(#[from] crate::queue::QueueError),
}

/// Ed25519 agent key. The seed is never printed by `Debug`.
pub struct AgentKey {
    seed: Zeroizing<[u8; 32]>,
    tenant_id: String,
    agent_id: String,
    actor: String,
    key_id: String,
    generation: u32,
    status: String,
    ed25519_public: [u8; 32],
    x25519_public: [u8; 32],
    created_at: String,
}

impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("tenant_id", &self.tenant_id)
            .field("agent_id", &self.agent_id)
            .field("actor", &self.actor)
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("ed25519_public", &b64::encode(&self.ed25519_public))
            .field("seed", &"[redacted]")
            .finish()
    }
}

impl AgentKey {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn status(&self) -> &str {
        &self.status
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
            tenant_id: self.tenant_id.clone(),
            agent_id: self.agent_id.clone(),
            actor: self.actor.clone(),
            key_id: self.key_id.clone(),
            generation: self.generation,
            status: self.status.clone(),
            ed25519_public_key: b64::encode(&self.ed25519_public),
            x25519_public_key: b64::encode(&self.x25519_public),
            alg_sign: "ed25519".to_string(),
            alg_enc: "x25519".to_string(),
            created_at: self.created_at.clone(),
        }
    }

    /// Rebuilds a key from its 32-byte ed25519 seed. The seed is the private key.
    pub fn from_seed(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        mut seed: [u8; 32],
        created_at: DateTime<Utc>,
        generation: u32,
    ) -> Result<Self, KeyError> {
        let built = assemble(
            &tenant_id.into(),
            &agent_id.into(),
            &seed,
            created_at,
            generation,
            STATUS_ACTIVE,
        );
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
    pub tenant_id: String,
    pub agent_id: String,
    pub actor: String,
    pub key_id: String,
    pub generation: u32,
    pub status: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    pub alg_sign: String,
    pub alg_enc: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    schema: String,
    tenant_id: String,
    agent_id: String,
    actor: String,
    key_id: String,
    generation: u32,
    status: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at: Option<String>,
    #[serde(default)]
    seed_shredded: bool,
    ed25519_seed: String,
    ed25519_public: String,
    x25519_public: String,
}

pub fn data_home() -> Result<PathBuf, KeyError> {
    if let Some(dir) = nonempty_env("CERVEAU_DATA_HOME").or_else(|| nonempty_env("CERVEAU_HOME")) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = nonempty_env("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("cerveau"));
    }
    let home = std::env::var("HOME").map_err(|_| KeyError::Home)?;
    Ok(PathBuf::from(home).join(".local/share/cerveau"))
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn agent_dir(data_dir: &Path, tenant_id: &str, agent_id: &str) -> Result<PathBuf, KeyError> {
    if !is_tenant_id(tenant_id) {
        return Err(KeyError::Tenant);
    }
    if !is_agent_id(agent_id) {
        return Err(KeyError::AgentId);
    }
    Ok(data_dir
        .join("tenants")
        .join(tenant_id)
        .join("agents")
        .join(dir_component(agent_id)?))
}

pub fn generate_agent_key(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
) -> Result<PublicExport, KeyError> {
    let dir = agent_dir(data_dir, tenant_id, agent_id)?;
    util::ensure_dir(&dir)?;
    let path = dir.join("key.json");
    if path.exists() {
        return Err(KeyError::AlreadyExists);
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let created = Utc::now();
    let key = AgentKey::from_seed(tenant_id, agent_id, seed, created, 1)?;
    write_key(&dir, &key)?;
    Ok(key.public_export())
}

pub fn load_agent_key(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
) -> Result<AgentKey, KeyError> {
    let dir = agent_dir(data_dir, tenant_id, agent_id)?;
    let path = dir.join("key.json");
    if !path.exists() {
        return Err(KeyError::NotFound);
    }
    let key = read_key_file(&path, false)?;
    if key.tenant_id != tenant_id || key.agent_id != agent_id {
        return Err(KeyError::AgentMismatch);
    }
    if key.status != STATUS_ACTIVE {
        return Err(KeyError::Retired);
    }
    Ok(key)
}

/// Issues a new active key and retires the previous one.
///
/// `next_seq` and queued runs move with the agent, not with the key. Queued
/// runs are re-encrypted under the new key. Their `seq` values do not change.
/// The retired seed is shredded after that migration.
pub fn rotate_agent_key(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
) -> Result<PublicExport, KeyError> {
    let old = load_agent_key(data_dir, tenant_id, agent_id)?;
    let dir = agent_dir(data_dir, tenant_id, agent_id)?;
    let store = QueueStore::acquire(&dir)?;
    let queued = if dir.join("queue.q").exists() {
        Some(store.load(&old)?)
    } else {
        None
    };
    write_retired(&dir, &old, STATUS_RETIRED, false)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let created = Utc::now();
    let generation = old.generation.saturating_add(1);
    let new_key = AgentKey::from_seed(tenant_id, agent_id, seed, created, generation)?;
    write_key(&dir, &new_key)?;
    if let Some(state) = queued {
        store.store(&new_key, &state)?;
    }
    shred_retired_seed(&dir, old.key_id())?;
    Ok(new_key.public_export())
}

/// Marks a retired key revoked and shreds any seed still on disk.
/// The active key is not revoked in place: rotate it first.
pub fn revoke_key(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
    key_id: &str,
) -> Result<(), KeyError> {
    if !is_key_id(key_id) {
        return Err(KeyError::KeyId);
    }
    let active = load_agent_key(data_dir, tenant_id, agent_id)?;
    if active.key_id() == key_id {
        return Err(KeyError::Retired);
    }
    let dir = agent_dir(data_dir, tenant_id, agent_id)?;
    let path = retired_path(&dir, key_id);
    if !path.exists() {
        return Err(KeyError::NotFound);
    }
    let mut file = read_key_file_raw(&path)?;
    file.status = STATUS_REVOKED.to_string();
    file.retired_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    file.seed_shredded = true;
    file.ed25519_seed.clear();
    write_key_file(&path, &file)?;
    Ok(())
}

pub fn retired_records(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Vec<PublicExport>, KeyError> {
    let dir = agent_dir(data_dir, tenant_id, agent_id)?;
    let retired = dir.join("retired");
    if !retired.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&retired)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let key = read_key_file(&path, true)?;
        out.push(key.public_export());
    }
    out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    Ok(out)
}

/// Opens the queue with the active key, or with a retired seed if a crash
/// interrupted migration, then re-encrypts it under the active key.
pub fn load_queue_state(
    data_dir: &Path,
    key: &AgentKey,
) -> Result<(QueueStore, QueueState), KeyError> {
    let dir = agent_dir(data_dir, key.tenant_id(), key.agent_id())?;
    let store = QueueStore::acquire(&dir)?;
    match store.load(key) {
        Ok(state) => Ok((store, state)),
        Err(crate::queue::QueueError::Corrupt) if dir.join("queue.q").exists() => {
            let recovered = recover_queue(&dir, &store)?;
            store.store(key, &recovered)?;
            Ok((store, recovered))
        }
        Err(err) => Err(err.into()),
    }
}

fn recover_queue(dir: &Path, store: &QueueStore) -> Result<QueueState, KeyError> {
    let retired = dir.join("retired");
    if !retired.exists() {
        return Err(KeyError::Corrupt);
    }
    for entry in fs::read_dir(&retired)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(key) = read_key_file(&path, true) else {
            continue;
        };
        if key.seed.iter().all(|b| *b == 0) {
            continue;
        }
        if let Ok(state) = store.load(&key) {
            shred_retired_seed(dir, key.key_id())?;
            return Ok(state);
        }
    }
    Err(KeyError::Corrupt)
}

fn write_key(dir: &Path, key: &AgentKey) -> Result<(), KeyError> {
    let file = key_file_from(key, None);
    let path = dir.join("key.json");
    write_key_file(&path, &file)
}

fn write_retired(dir: &Path, key: &AgentKey, status: &str, shred: bool) -> Result<(), KeyError> {
    let mut file = key_file_from(
        key,
        Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    file.status = status.to_string();
    if shred {
        file.seed_shredded = true;
        file.ed25519_seed.clear();
    }
    let path = retired_path(dir, key.key_id());
    if let Some(parent) = path.parent() {
        util::ensure_dir(parent)?;
    }
    write_key_file(&path, &file)
}

fn shred_retired_seed(dir: &Path, key_id: &str) -> Result<(), KeyError> {
    let path = retired_path(dir, key_id);
    if !path.exists() {
        return Ok(());
    }
    let mut file = read_key_file_raw(&path)?;
    file.seed_shredded = true;
    file.ed25519_seed.clear();
    if file.status == STATUS_ACTIVE {
        file.status = STATUS_RETIRED.to_string();
    }
    write_key_file(&path, &file)
}

fn retired_path(dir: &Path, key_id: &str) -> PathBuf {
    dir.join("retired").join(format!("{key_id}.json"))
}

fn key_file_from(key: &AgentKey, retired_at: Option<String>) -> KeyFile {
    KeyFile {
        schema: KEY_SCHEMA.to_string(),
        tenant_id: key.tenant_id.clone(),
        agent_id: key.agent_id.clone(),
        actor: key.actor.clone(),
        key_id: key.key_id.clone(),
        generation: key.generation,
        status: key.status.clone(),
        created_at: key.created_at.clone(),
        retired_at,
        seed_shredded: false,
        ed25519_seed: b64::encode(key.seed()),
        ed25519_public: b64::encode(key.ed25519_public()),
        x25519_public: b64::encode(key.x25519_public()),
    }
}

fn write_key_file(path: &Path, file: &KeyFile) -> Result<(), KeyError> {
    let mut bytes = serde_json::to_vec_pretty(file).map_err(|_| KeyError::Corrupt)?;
    bytes.push(b'\n');
    let parent = path.parent().ok_or(KeyError::Corrupt)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(KeyError::Corrupt)?;
    util::write_durable(parent, name, &bytes)?;
    bytes.zeroize();
    Ok(())
}

fn read_key_file(path: &Path, allow_shredded: bool) -> Result<AgentKey, KeyError> {
    ensure_private(path).map_err(|_| KeyError::Permissions)?;
    let file = read_key_file_raw(path)?;
    if file.schema != KEY_SCHEMA || !is_key_id(&file.key_id) || !is_tenant_id(&file.tenant_id) {
        return Err(KeyError::Corrupt);
    }
    let created = DateTime::parse_from_rfc3339(&file.created_at)
        .map_err(|_| KeyError::Corrupt)?
        .with_timezone(&Utc);
    if file.seed_shredded || file.ed25519_seed.is_empty() {
        if !allow_shredded {
            return Err(KeyError::Corrupt);
        }
        let mut key = assemble(
            &file.tenant_id,
            &file.agent_id,
            &[0u8; 32],
            created,
            file.generation,
            &file.status,
        )?;
        key.ed25519_public =
            b64::decode_array(file.ed25519_public.trim()).map_err(|_| KeyError::Corrupt)?;
        key.x25519_public =
            b64::decode_array(file.x25519_public.trim()).map_err(|_| KeyError::Corrupt)?;
        key.seed = Zeroizing::new([0u8; 32]);
        if key.key_id != file.key_id || key.actor != file.actor {
            return Err(KeyError::Corrupt);
        }
        return Ok(key);
    }
    let seed: [u8; 32] =
        b64::decode_array(file.ed25519_seed.trim()).map_err(|_| KeyError::Corrupt)?;
    let key = assemble(
        &file.tenant_id,
        &file.agent_id,
        &seed,
        created,
        file.generation,
        &file.status,
    )?;
    if key.key_id != file.key_id
        || key.actor != file.actor
        || key.status != file.status
        || b64::encode(key.ed25519_public()) != file.ed25519_public
        || b64::encode(key.x25519_public()) != file.x25519_public
    {
        return Err(KeyError::Corrupt);
    }
    Ok(key)
}

fn read_key_file_raw(path: &Path) -> Result<KeyFile, KeyError> {
    ensure_private(path).map_err(|_| KeyError::Permissions)?;
    let mut bytes = fs::read(path)?;
    let parsed: Result<KeyFile, _> = serde_json::from_slice(&bytes);
    bytes.zeroize();
    parsed.map_err(|_| KeyError::Corrupt)
}

fn assemble(
    tenant_id: &str,
    agent_id: &str,
    seed: &[u8; 32],
    created_at: DateTime<Utc>,
    generation: u32,
    status: &str,
) -> Result<AgentKey, KeyError> {
    if !is_tenant_id(tenant_id) {
        return Err(KeyError::Tenant);
    }
    if !is_agent_id(agent_id) {
        return Err(KeyError::AgentId);
    }
    let signing = SigningKey::from_bytes(seed);
    let ed25519_public = signing.verifying_key().to_bytes();
    let x_secret = ed25519_seed_to_x25519_secret(seed);
    let x25519_public = x25519_public(&x_secret);
    let actor = actor_for(tenant_id, agent_id);
    let key_id = key_id_for(tenant_id, agent_id, created_at, generation)?;
    if !id::is_safe_actor(&actor) {
        return Err(KeyError::AgentId);
    }
    Ok(AgentKey {
        seed: Zeroizing::new(*seed),
        tenant_id: tenant_id.to_string(),
        agent_id: agent_id.to_string(),
        actor,
        key_id,
        generation,
        status: status.to_string(),
        ed25519_public,
        x25519_public,
        created_at: created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub(crate) fn actor_for(tenant_id: &str, agent_id: &str) -> String {
    let bare = agent_id.strip_prefix("gb:").unwrap_or(agent_id);
    format!("gb:{tenant_id}:{bare}")
}

pub(crate) fn key_id_for(
    tenant_id: &str,
    agent_id: &str,
    created: DateTime<Utc>,
    generation: u32,
) -> Result<String, KeyError> {
    if generation == 0 || generation > 9_999 {
        return Err(KeyError::KeyId);
    }
    let safe = dir_component(agent_id)?;
    let key_id = format!(
        "gb-{tenant_id}-{safe}-{}-{generation}",
        created.format("%Y%m")
    );
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
    use crate::body::{prepare_body, RunInput};
    use crate::crypto;
    use crate::queue::QueuedRun;
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
        let export = generate_agent_key(&home, "tenant-test", "agent-test").unwrap();
        assert!(is_key_id(&export.key_id));
        assert!(export.key_id.starts_with("gb-tenant-test-agent-test-"));
        assert_eq!(export.actor, "gb:tenant-test:agent-test");
        assert_eq!(export.generation, 1);
        let path = agent_dir(&home, "tenant-test", "agent-test")
            .unwrap()
            .join("key.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let raw = fs::read_to_string(&path).unwrap();
        let key = load_agent_key(&home, "tenant-test", "agent-test").unwrap();
        let debug = format!("{key:?}");
        let seed_b64 = {
            let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
            file["ed25519_seed"].as_str().unwrap().to_string()
        };
        assert!(!debug.contains(&seed_b64));
        assert!(debug.contains("[redacted]"));
        let stdout = serde_json::to_string(&export).unwrap();
        assert!(!stdout.contains(&seed_b64));
        assert!(generate_agent_key(&home, "tenant-test", "agent-test").is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn open_permissions_and_bad_key_id_are_refused() {
        let home = scratch();
        generate_agent_key(&home, "tenant-test", "agent-test").unwrap();
        let path = agent_dir(&home, "tenant-test", "agent-test")
            .unwrap()
            .join("key.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_agent_key(&home, "tenant-test", "agent-test"),
            Err(KeyError::Permissions)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value["key_id"] = serde_json::Value::String("not a key".into());
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_agent_key(&home, "tenant-test", "agent-test").is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn x25519_public_matches_edwards_conversion() {
        let key = AgentKey::from_seed(
            "tenant-test",
            "agent-test",
            [7u8; 32],
            DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            1,
        )
        .unwrap();
        let converted = crypto::ed25519_public_to_x25519(key.ed25519_public()).unwrap();
        assert_eq!(converted, *key.x25519_public());
        assert_eq!(key.key_id(), "gb-tenant-test-agent-test-202610-1");
        assert_eq!(key.actor(), "gb:tenant-test:agent-test");
    }

    #[test]
    fn rotation_keeps_seq_and_shreds_the_retired_seed() {
        let home = scratch();
        generate_agent_key(&home, "tenant-test", "agent-test").unwrap();
        let old = load_agent_key(&home, "tenant-test", "agent-test").unwrap();
        let old_id = old.key_id().to_string();
        let old_seed = b64::encode(old.seed());
        let dir = agent_dir(&home, "tenant-test", "agent-test").unwrap();
        let store = QueueStore::acquire(&dir).unwrap();
        let body = prepare_body(RunInput {
            tenant_id: "tenant-test".into(),
            principal_id: "p_owner".into(),
            transcript: "keep-me".into(),
            ..RunInput::default()
        })
        .unwrap();
        let state = QueueState {
            next_seq: 4,
            records: vec![QueuedRun {
                run_id: "run_KEEP".into(),
                seq: 3,
                sent_at: "2026-10-22T15:44:58Z".into(),
                principal_id: "p_owner".into(),
                body,
            }],
        };
        store.store(&old, &state).unwrap();
        drop(store);
        let exported = rotate_agent_key(&home, "tenant-test", "agent-test").unwrap();
        assert_ne!(exported.key_id, old_id);
        assert_eq!(exported.generation, 2);
        assert!(exported.key_id.ends_with("-2"));
        let active = load_agent_key(&home, "tenant-test", "agent-test").unwrap();
        let (_store, loaded) = load_queue_state(&home, &active).unwrap();
        assert_eq!(loaded.next_seq, 4);
        assert_eq!(loaded.records[0].seq, 3);
        assert_eq!(loaded.records[0].run_id, "run_KEEP");
        let retired =
            fs::read_to_string(dir.join("retired").join(format!("{old_id}.json"))).unwrap();
        assert!(!retired.contains(&old_seed));
        assert!(retired.contains("\"seed_shredded\": true"));
        assert!(retired.contains("\"status\": \"retired\""));
        revoke_key(&home, "tenant-test", "agent-test", &old_id).unwrap();
        let revoked =
            fs::read_to_string(dir.join("retired").join(format!("{old_id}.json"))).unwrap();
        assert!(revoked.contains("\"status\": \"revoked\""));
        assert!(revoke_key(&home, "tenant-test", "agent-test", active.key_id()).is_err());
        let _ = fs::remove_dir_all(home);
    }
}
