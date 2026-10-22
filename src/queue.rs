use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::body::RunBody;
use crate::crypto::{self, aead_open, aead_seal, hkdf_sha256};
use crate::id::{is_run_id, is_user_id};
use crate::key::AgentKey;
use crate::util::{self, ensure_private};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const QUEUE_SCHEMA: &str = "gb.queue.v2";
const MAGIC: &[u8; 4] = b"GBQ2";
const QUEUE_AAD: &[u8] = b"gb.queue.v2";

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("queue is corrupt")]
    Corrupt,
    #[error("queue permissions are too open")]
    Permissions,
    #[error("queue belongs to another agent")]
    Agent,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct QueuedRun {
    pub run_id: String,
    pub seq: u64,
    pub sent_at: String,
    pub user_id: String,
    pub body: RunBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskQueue {
    schema: String,
    tenant_id: String,
    agent_id: String,
    key_id: String,
    next_seq: u64,
    records: Vec<QueuedRun>,
}

#[derive(Debug, Clone)]
pub(crate) struct QueueState {
    pub next_seq: u64,
    pub records: Vec<QueuedRun>,
}

pub(crate) struct QueueStore {
    dir: std::path::PathBuf,
    lock: std::fs::File,
}

impl Drop for QueueStore {
    fn drop(&mut self) {
        // Closing this fd releases the advisory lock. std::fs::File::unlock
        // is newer than the crate MSRV, so the lock is released by Drop of the fd.
        let _fd = &self.lock;
    }
}

impl QueueStore {
    pub fn acquire(dir: &Path) -> Result<Self, QueueError> {
        util::ensure_dir(dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("lock"))?;
        lock.lock_exclusive()?;
        Ok(Self {
            dir: dir.to_path_buf(),
            lock,
        })
    }

    pub fn load(&self, key: &AgentKey) -> Result<QueueState, QueueError> {
        let path = self.dir.join("queue.q");
        if !path.exists() {
            return Ok(QueueState {
                next_seq: 1,
                records: Vec::new(),
            });
        }
        ensure_private(&path).map_err(|_| QueueError::Permissions)?;
        let bytes = std::fs::read(&path)?;
        let plain = decrypt(key, &bytes)?;
        let disk: DiskQueue = serde_json::from_slice(&plain).map_err(|_| QueueError::Corrupt)?;
        if disk.schema != QUEUE_SCHEMA
            || disk.tenant_id != key.tenant_id()
            || disk.agent_id != key.agent_id()
            || disk.key_id != key.key_id()
        {
            return Err(QueueError::Agent);
        }
        if disk.next_seq == 0 {
            return Err(QueueError::Corrupt);
        }
        let mut records = disk.records;
        records.sort_by_key(|m| m.seq);
        let mut seen_seq = std::collections::BTreeSet::new();
        let mut seen_run = std::collections::BTreeSet::new();
        for record in &mut records {
            if record.seq == 0 || record.seq >= disk.next_seq {
                return Err(QueueError::Corrupt);
            }
            if !is_run_id(&record.run_id) || !is_user_id(&record.user_id) {
                return Err(QueueError::Corrupt);
            }
            if record.body.tenant_id != disk.tenant_id {
                return Err(QueueError::Corrupt);
            }
            if record.body.user_id.is_empty() {
                record.body.user_id = record.user_id.clone();
            } else if record.body.user_id != record.user_id {
                return Err(QueueError::Corrupt);
            }
            if !seen_seq.insert(record.seq) || !seen_run.insert(record.run_id.clone()) {
                return Err(QueueError::Corrupt);
            }
        }
        Ok(QueueState {
            next_seq: disk.next_seq,
            records,
        })
    }

    pub fn store(&self, key: &AgentKey, state: &QueueState) -> Result<(), QueueError> {
        let disk = DiskQueue {
            schema: QUEUE_SCHEMA.to_string(),
            tenant_id: key.tenant_id().to_string(),
            agent_id: key.agent_id().to_string(),
            key_id: key.key_id().to_string(),
            next_seq: state.next_seq,
            records: state.records.clone(),
        };
        let plain = serde_json::to_vec(&disk).map_err(|_| QueueError::Corrupt)?;
        let blob = encrypt(key, &plain)?;
        util::write_durable(&self.dir, "queue.q", &blob)?;
        Ok(())
    }
}

fn queue_key(key: &AgentKey) -> Result<[u8; 32], QueueError> {
    let mut info = Vec::new();
    info.extend_from_slice(b"gb.queue.v2\x00");
    info.extend_from_slice(key.tenant_id().as_bytes());
    info.extend_from_slice(b"\x00");
    info.extend_from_slice(key.agent_id().as_bytes());
    info.extend_from_slice(b"\x00");
    info.extend_from_slice(key.key_id().as_bytes());
    hkdf_sha256(b"gb.queue.v2", key.seed(), &info).map_err(|_| QueueError::Corrupt)
}

fn encrypt(key: &AgentKey, plaintext: &[u8]) -> Result<Vec<u8>, QueueError> {
    let mut aead_key = queue_key(key)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let ct = aead_seal(&aead_key, &nonce, QUEUE_AAD, plaintext).map_err(|_| QueueError::Corrupt)?;
    crypto::zeroize_key(&mut aead_key);
    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &AgentKey, bytes: &[u8]) -> Result<Vec<u8>, QueueError> {
    if bytes.len() < 4 + 12 + 16 || &bytes[..4] != MAGIC {
        return Err(QueueError::Corrupt);
    }
    let nonce = &bytes[4..16];
    let ct = &bytes[16..];
    let mut aead_key = queue_key(key)?;
    let plain = aead_open(&aead_key, nonce, QUEUE_AAD, ct).map_err(|_| QueueError::Corrupt)?;
    crypto::zeroize_key(&mut aead_key);
    Ok(plain)
}

pub(crate) fn new_run_id() -> Result<String, QueueError> {
    let run_id = format!("run_{}", ulid::Ulid::new());
    if !is_run_id(&run_id) {
        return Err(QueueError::Corrupt);
    }
    Ok(run_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::{prepare_body, RunInput};
    use crate::key::AgentKey;
    use chrono::{DateTime, Utc};
    use std::os::unix::fs::PermissionsExt;

    fn scratch() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cerveau-q-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn agent() -> AgentKey {
        AgentKey::from_seed(
            "tenant-test",
            "agent-test",
            [3u8; 32],
            DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            1,
        )
        .unwrap()
    }

    fn queued(seq: u64, marker: &str) -> QueuedRun {
        let body = prepare_body(RunInput {
            tenant_id: "tenant-test".into(),
            user_id: "p_owner".into(),
            transcript: marker.to_string(),
            ..RunInput::default()
        })
        .unwrap();
        QueuedRun {
            run_id: format!("run_SEQ{seq}"),
            seq,
            sent_at: "2026-10-22T15:44:58Z".into(),
            user_id: "p_owner".into(),
            body,
        }
    }

    #[test]
    fn durable_file_is_encrypted_sorted_and_reopens() {
        let dir = scratch();
        let agent = agent();
        let marker = "PLAINTEXT_MARKER_9f3a";
        let store = QueueStore::acquire(&dir).unwrap();
        let mut state = store.load(&agent).unwrap();
        state.records.push(queued(2, marker));
        state.records.push(queued(1, marker));
        state.next_seq = 3;
        store.store(&agent, &state).unwrap();
        drop(store);

        let bytes = std::fs::read(dir.join("queue.q")).unwrap();
        assert!(bytes.starts_with(b"GBQ2"));
        assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
        let mode = std::fs::metadata(dir.join("queue.q"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let store = QueueStore::acquire(&dir).unwrap();
        let loaded = store.load(&agent).unwrap();
        assert_eq!(
            loaded.records.iter().map(|m| m.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        std::fs::write(dir.join("queue.q.tmp"), b"partial").unwrap();
        let again = store.load(&agent).unwrap();
        assert_eq!(again.records.len(), 2);

        std::fs::set_permissions(dir.join("queue.q"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(store.load(&agent), Err(QueueError::Permissions)));
        let _ = std::fs::remove_dir_all(dir);
    }
}
