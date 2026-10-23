//! Signature MCP profil `eg-mcp-sig-1`. Même base que le serveur :
//! RFC 9421, label `mcp`, ed25519. La graine reste dans le fichier 0600.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::b64;
use crate::id::is_key_id;
use crate::mcp_eg::EgError;
use crate::util;

pub const SIGNING_SCHEMA: &str = "eg.mcp_signing_key.v1";

pub struct SigningFile {
    key_id: String,
    seed: Zeroizing<[u8; 32]>,
}

impl Drop for SigningFile {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl SigningFile {
    pub fn load(path: &Path) -> Result<Self, EgError> {
        let meta = fs::symlink_metadata(path).map_err(|_| EgError::Token("unreadable".into()))?;
        if meta.file_type().is_symlink() {
            return Err(EgError::Token("symlink refused".into()));
        }
        if !meta.file_type().is_file() {
            return Err(EgError::Token("not a file".into()));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(EgError::Token(format!("mode {mode:o} is not 0600")));
        }
        let raw = fs::read(path).map_err(|_| EgError::Token("unreadable".into()))?;
        let file: Stored = serde_json::from_slice(&raw).map_err(|_| EgError::Token("rejected".into()))?;
        if file.schema != SIGNING_SCHEMA || !is_mcp_key_id(&file.key_id) {
            return Err(EgError::Token("rejected".into()));
        }
        let seed = b64::decode_array(file.seed.trim()).map_err(|_| EgError::Token("rejected".into()))?;
        Ok(Self {
            key_id: file.key_id,
            seed: Zeroizing::new(seed),
        })
    }

    pub fn sign(&self, request: &SignRequest<'_>) -> Result<SignedHeaders, EgError> {
        if !safe(&request.method) || !safe(&request.authority) || !safe(&request.path) || !safe(&request.content_type)
        {
            return Err(EgError::Endpoint("invalid".into()));
        }
        if let Some(session) = request.session_id {
            if !safe(session) {
                return Err(EgError::Endpoint("invalid".into()));
            }
        }
        let digest = content_digest(request.body);
        let input = signature_input(request.session_id.is_some(), request.created, &self.key_id);
        let base = signature_base(
            request.method,
            request.authority,
            request.path,
            &digest,
            request.content_type,
            request.session_id,
            request.created,
            &self.key_id,
        );
        let key = SigningKey::from_bytes(&self.seed);
        let sig = key.sign(base.as_bytes());
        Ok(SignedHeaders {
            content_digest: digest,
            signature_input: input,
            signature: format!("mcp=:{}:", STANDARD.encode(sig.to_bytes())),
        })
    }
}

pub struct SignRequest<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub content_type: &'a str,
    pub body: &'a [u8],
    pub session_id: Option<&'a str>,
    pub created: i64,
}

pub struct SignedHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    schema: String,
    key_id: String,
    seed: String,
}

pub fn default_signing_path(config_dir: &Path) -> PathBuf {
    config_dir.join("mcp-signing-key")
}

/// Crée le fichier s'il n'existe pas. Ne renvoie que la publique.
pub fn generate(directory: &Path, key_id: &str) -> Result<String, EgError> {
    if !is_mcp_key_id(key_id) {
        return Err(EgError::Token("rejected".into()));
    }
    let path = default_signing_path(directory);
    if path.exists() {
        return Err(EgError::Token("refusing to overwrite".into()));
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let public = public_of(&seed);
    let stored = Stored {
        schema: SIGNING_SCHEMA.into(),
        key_id: key_id.into(),
        seed: b64::encode(&seed),
    };
    seed.zeroize();
    let bytes = serde_json::to_vec(&stored).map_err(|_| EgError::Token("rejected".into()))?;
    util::write_durable(directory, "mcp-signing-key", &bytes).map_err(|_| EgError::Token("unreadable".into()))?;
    Ok(public)
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub fn authority_of(url: &str) -> Result<String, EgError> {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') || !safe(host) {
        return Err(EgError::Endpoint("invalid".into()));
    }
    Ok(host.to_ascii_lowercase())
}

fn public_of(seed: &[u8; 32]) -> String {
    STANDARD.encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

fn signature_input(with_session: bool, created: i64, key_id: &str) -> String {
    let covered = if with_session {
        "(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"mcp-session-id\")"
    } else {
        "(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\")"
    };
    format!("mcp={covered};created={created};keyid=\"{key_id}\";alg=\"ed25519\"")
}

fn signature_base(
    method: &str,
    authority: &str,
    path: &str,
    digest: &str,
    content_type: &str,
    session: Option<&str>,
    created: i64,
    key_id: &str,
) -> String {
    let mut lines = vec![
        format!("\"@method\": {method}"),
        format!("\"@authority\": {authority}"),
        format!("\"@path\": {path}"),
        format!("\"content-digest\": {digest}"),
        format!("\"content-type\": {content_type}"),
    ];
    if let Some(session) = session {
        lines.push(format!("\"mcp-session-id\": {session}"));
    }
    let params = signature_input(session.is_some(), created, key_id);
    let params = params.trim_start_matches("mcp=");
    lines.push(format!("\"@signature-params\": {params}"));
    lines.join("\n")
}

fn is_mcp_key_id(value: &str) -> bool {
    (1..=64).contains(&value.len()) && is_key_id(value)
}

fn safe(value: &str) -> bool {
    !value.is_empty() && value.is_ascii() && !value.bytes().any(|b| b == b'\n' || b == b'\r' || b == b'"')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    #[test]
    fn signature_base_matches_the_server_profile() {
        let digest = content_digest(b"{}");
        assert_eq!(digest, "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:");
        let base = signature_base(
            "POST",
            "mcp.cdxxotus.com",
            "/mcp",
            &digest,
            "application/json",
            None,
            1_760_000_000,
            "box-test",
        );
        assert_eq!(
            base,
            "\"@method\": POST\n\"@authority\": mcp.cdxxotus.com\n\"@path\": /mcp\n\"content-digest\": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:\n\"content-type\": application/json\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\");created=1760000000;keyid=\"box-test\";alg=\"ed25519\""
        );
    }

    #[test]
    fn a_loaded_key_signs_the_profile_and_hides_the_seed() {
        let root = std::env::temp_dir().join(format!("mcp-sig-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let public = generate(&root, "box-test").unwrap();
        assert_eq!(public.len(), 44);
        assert!(!public.contains("seed"));
        let path = default_signing_path(&root);
        let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let stored = fs::read_to_string(&path).unwrap();
        assert!(stored.contains("ed25519") || stored.contains("seed"));
        let key = SigningFile::load(&path).unwrap();
        let signed = key
            .sign(&SignRequest {
                method: "POST",
                authority: "mcp.cdxxotus.com",
                path: "/mcp",
                content_type: "application/json",
                body: b"{}",
                session_id: None,
                created: 1_760_000_000,
            })
            .unwrap();
        assert!(signed.signature.starts_with("mcp=:"));
        assert!(!signed.signature_input.contains(&stored));
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(
            &STANDARD.decode(&public).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let digest = content_digest(b"{}");
        let base = signature_base(
            "POST",
            "mcp.cdxxotus.com",
            "/mcp",
            &digest,
            "application/json",
            None,
            1_760_000_000,
            "box-test",
        );
        let raw = STANDARD
            .decode(signed.signature.trim_start_matches("mcp=:").trim_end_matches(':'))
            .unwrap();
        verifying
            .verify(base.as_bytes(), &ed25519_dalek::Signature::from_slice(&raw).unwrap())
            .unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn open_mode_and_symlink_are_refused() {
        let root = std::env::temp_dir().join(format!("mcp-sig-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = default_signing_path(&root);
        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o644)
                .open(&path)
                .unwrap();
            use std::io::Write;
            writeln!(file, "{{}}").unwrap();
        }
        assert!(SigningFile::load(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, "x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(SigningFile::load(&link).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn generate_does_not_overwrite() {
        let root = std::env::temp_dir().join(format!("mcp-sig-once-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        assert!(generate(&root, "box-test").is_ok());
        assert!(generate(&root, "box-test").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
