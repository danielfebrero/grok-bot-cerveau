//! Clé du compte, sur la box. La graine ne sort pas. Le bundle public
//! est ce que le serveur enregistre. Sans ce fichier, le `gb.run` n'a
//! pas de preuve de compte.

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
use crate::id::{is_key_id, is_principal_id, is_tenant_id};
use crate::util::{self, ensure_private};

pub const ACCOUNT_KEY_SCHEMA: &str = "gb.account_key.v1";
pub const ACCOUNT_PUB_SCHEMA: &str = "gb.account_pub.v1";

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("tenant id is not an ASCII token of [A-Za-z0-9_-]")]
    Tenant,
    #[error("account user id is not an ASCII token of [A-Za-z0-9_-]")]
    User,
    #[error("key id is not an ASCII token of [A-Za-z0-9_-]")]
    KeyId,
    #[error("account key not found")]
    NotFound,
    #[error("account key file is inconsistent")]
    Corrupt,
    #[error("account key permissions are too open")]
    Permissions,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Private account key. The seed is not in `Debug`.
pub struct AccountKey {
    seed: Zeroizing<[u8; 32]>,
    tenant_id: String,
    user_id: String,
    key_id: String,
    ed25519_public: [u8; 32],
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountKey")
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl AccountKey {
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_public
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    pub fn public_export(&self) -> AccountPublic {
        AccountPublic {
            schema: ACCOUNT_PUB_SCHEMA.to_string(),
            tenant_id: self.tenant_id.clone(),
            user_id: self.user_id.clone(),
            key_id: self.key_id.clone(),
            ed25519_public_key: b64::encode(&self.ed25519_public),
        }
    }

    pub(crate) fn from_parts(
        tenant_id: &str,
        user_id: &str,
        key_id: &str,
        seed: [u8; 32],
    ) -> Result<Self, AccountError> {
        if !is_tenant_id(tenant_id) {
            return Err(AccountError::Tenant);
        }
        if !is_principal_id(user_id) {
            return Err(AccountError::User);
        }
        if !is_key_id(key_id) {
            return Err(AccountError::KeyId);
        }
        let signing = SigningKey::from_bytes(&seed);
        Ok(Self {
            seed: Zeroizing::new(seed),
            tenant_id: tenant_id.to_string(),
            user_id: user_id.to_string(),
            key_id: key_id.to_string(),
            ed25519_public: signing.verifying_key().to_bytes(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPublic {
    pub schema: String,
    pub tenant_id: String,
    pub user_id: String,
    pub key_id: String,
    pub ed25519_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct AccountFile {
    schema: String,
    tenant_id: String,
    user_id: String,
    key_id: String,
    created_at: String,
    ed25519_seed: String,
    ed25519_public: String,
}

/// Creates the account key, or returns the one already on disk.
/// The returned value has no seed.
pub fn account_public(
    data_dir: &Path,
    tenant_id: &str,
    user_id: &str,
) -> Result<AccountPublic, AccountError> {
    match load_account_key(data_dir, tenant_id, user_id) {
        Ok(key) => return Ok(key.public_export()),
        Err(AccountError::NotFound) => {}
        Err(err) => return Err(err),
    }
    let created = Utc::now();
    let key_id = account_key_id(tenant_id, user_id, created)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = AccountKey::from_parts(tenant_id, user_id, &key_id, seed)?;
    seed.zeroize();
    write_account_file(&account_path(data_dir, tenant_id, user_id)?, &key, created)?;
    Ok(key.public_export())
}

pub(crate) fn load_account_key(
    data_dir: &Path,
    tenant_id: &str,
    user_id: &str,
) -> Result<AccountKey, AccountError> {
    let path = account_path(data_dir, tenant_id, user_id)?;
    if !path.exists() {
        return Err(AccountError::NotFound);
    }
    ensure_private(&path).map_err(|_| AccountError::Permissions)?;
    let mut bytes = fs::read(&path)?;
    let parsed: Result<AccountFile, _> = serde_json::from_slice(&bytes);
    bytes.zeroize();
    let file = parsed.map_err(|_| AccountError::Corrupt)?;
    if file.schema != ACCOUNT_KEY_SCHEMA
        || file.tenant_id != tenant_id
        || file.user_id != user_id
        || !is_key_id(&file.key_id)
    {
        return Err(AccountError::Corrupt);
    }
    let seed: [u8; 32] =
        b64::decode_array(file.ed25519_seed.trim()).map_err(|_| AccountError::Corrupt)?;
    let key = AccountKey::from_parts(tenant_id, user_id, &file.key_id, seed)?;
    if b64::encode(key.ed25519_public()) != file.ed25519_public {
        return Err(AccountError::Corrupt);
    }
    let _ = DateTime::parse_from_rfc3339(&file.created_at).map_err(|_| AccountError::Corrupt)?;
    Ok(key)
}

fn account_key_id(
    tenant_id: &str,
    user_id: &str,
    created: DateTime<Utc>,
) -> Result<String, AccountError> {
    if !is_tenant_id(tenant_id) {
        return Err(AccountError::Tenant);
    }
    if !is_principal_id(user_id) {
        return Err(AccountError::User);
    }
    let key_id = format!("compte-{tenant_id}-{user_id}-{}-1", created.format("%Y%m"));
    if !is_key_id(&key_id) {
        return Err(AccountError::KeyId);
    }
    Ok(key_id)
}

fn account_path(data_dir: &Path, tenant_id: &str, user_id: &str) -> Result<PathBuf, AccountError> {
    if !is_tenant_id(tenant_id) {
        return Err(AccountError::Tenant);
    }
    if !is_principal_id(user_id) {
        return Err(AccountError::User);
    }
    Ok(data_dir
        .join("tenants")
        .join(tenant_id)
        .join("accounts")
        .join(format!("{user_id}.json")))
}

fn write_account_file(
    path: &Path,
    key: &AccountKey,
    created: DateTime<Utc>,
) -> Result<(), AccountError> {
    let file = AccountFile {
        schema: ACCOUNT_KEY_SCHEMA.to_string(),
        tenant_id: key.tenant_id.clone(),
        user_id: key.user_id.clone(),
        key_id: key.key_id.clone(),
        created_at: created.to_rfc3339_opts(SecondsFormat::Secs, true),
        ed25519_seed: b64::encode(key.seed.as_slice()),
        ed25519_public: b64::encode(key.ed25519_public()),
    };
    let mut bytes = serde_json::to_vec_pretty(&file).map_err(|_| AccountError::Corrupt)?;
    bytes.push(b'\n');
    let parent = path.parent().ok_or(AccountError::Corrupt)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(AccountError::Corrupt)?;
    util::write_durable(parent, name, &bytes)?;
    bytes.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_account_key_stays_private_and_reloads() {
        let root = std::env::temp_dir().join(format!(
            "cerveau-account-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        let public = account_public(&root, "tenant-test", "u_owner").unwrap();
        assert_eq!(public.schema, ACCOUNT_PUB_SCHEMA);
        assert_eq!(public.user_id, "u_owner");
        assert!(public.key_id.starts_with("compte-tenant-test-u_owner-"));
        assert!(!public.ed25519_public_key.is_empty());
        let again = account_public(&root, "tenant-test", "u_owner").unwrap();
        assert_eq!(again, public);
        let path = account_path(&root, "tenant-test", "u_owner").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let stored = fs::read_to_string(&path).unwrap();
        assert!(stored.contains("ed25519_seed"));
        let exported = serde_json::to_string(&public).unwrap();
        assert!(!exported.contains("ed25519_seed"));
        let loaded = load_account_key(&root, "tenant-test", "u_owner").unwrap();
        assert_eq!(loaded.key_id(), public.key_id);
        assert_eq!(
            b64::encode(loaded.ed25519_public()),
            public.ed25519_public_key
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_account_key(&root, "tenant-test", "u_owner"),
            Err(AccountError::Permissions)
        ));
        let _ = fs::remove_dir_all(&root);
    }
}
