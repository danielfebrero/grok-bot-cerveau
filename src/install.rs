use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::b64;
use crate::client::{
    decode_env_key, nonempty, optional_endpoint, ClientConfig, ConfigError, DEFAULT_TOOL,
};
use crate::id::{is_key_id, is_principal_id, is_tenant_id};
use crate::key::{
    self, generate_agent_key, retired_records, PublicExport, STATUS_RETIRED, STATUS_REVOKED,
};
use crate::util;

pub const INSTALL_SCHEMA: &str = "gb.install.v1";
pub const REGISTER_SCHEMA: &str = "gb.register.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub principal_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerPin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallConfig {
    pub schema: String,
    pub tenant_id: String,
    pub principals: Vec<Principal>,
    pub server: ServerPin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationBundle {
    pub schema: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub principals: Vec<Principal>,
    pub actor: String,
    pub key_id: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    pub retired_key_ids: Vec<String>,
    pub revoked_key_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InitRequest {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub tenant_id: String,
    pub principal_id: String,
    pub display_name: String,
    pub agent_id: String,
    pub endpoint: Option<String>,
    pub recipient_key_id: Option<String>,
    pub recipient_public: Option<[u8; 32]>,
    pub signing_key_id: Option<String>,
    pub signing_public: Option<[u8; 32]>,
    pub tool_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PresentedServer {
    pub endpoint: Option<String>,
    pub recipient_key_id: Option<String>,
    pub recipient_public: Option<[u8; 32]>,
    pub signing_key_id: Option<String>,
    pub signing_public: Option<[u8; 32]>,
    pub trust_on_first_use: bool,
}

pub fn config_home() -> Result<PathBuf, ConfigError> {
    if let Some(dir) = nonempty("CERVEAU_CONFIG_HOME") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = nonempty("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("cerveau"));
    }
    let home = std::env::var("HOME").map_err(|_| ConfigError::Missing("HOME"))?;
    Ok(PathBuf::from(home).join(".config/cerveau"))
}

pub fn init_install(req: InitRequest) -> Result<(InstallConfig, PublicExport), ConfigError> {
    validate_identity(&req.tenant_id, &req.principal_id, &req.display_name)?;
    if install_path(&req.config_dir, &req.tenant_id).exists() {
        return Err(ConfigError::AlreadyInitialized);
    }
    let endpoint = match req.endpoint {
        Some(url) => Some(crate::client::validate_endpoint(&url)?),
        None => None,
    };
    let server = ServerPin {
        endpoint,
        recipient_key_id: req.recipient_key_id.clone(),
        recipient_public_key: req.recipient_public.map(|b| b64::encode(&b)),
        signing_key_id: req.signing_key_id.clone(),
        signing_public_key: req.signing_public.map(|b| b64::encode(&b)),
        tool_name: req.tool_name.clone(),
    };
    check_pin_shape(&server)?;
    let install = InstallConfig {
        schema: INSTALL_SCHEMA.to_string(),
        tenant_id: req.tenant_id.clone(),
        principals: vec![Principal {
            principal_id: req.principal_id,
            display_name: req.display_name,
        }],
        server,
    };
    save_install(&req.config_dir, &install)?;
    let export = generate_agent_key(&req.data_dir, &req.tenant_id, &req.agent_id)?;
    Ok((install, export))
}

pub fn add_principal(
    config_dir: &Path,
    tenant_id: &str,
    principal_id: &str,
    display_name: &str,
) -> Result<Principal, ConfigError> {
    validate_identity(tenant_id, principal_id, display_name)?;
    let mut install = load_install(config_dir, tenant_id)?;
    if install
        .principals
        .iter()
        .any(|p| p.principal_id == principal_id)
    {
        return Err(ConfigError::AlreadyInitialized);
    }
    let principal = Principal {
        principal_id: principal_id.to_string(),
        display_name: display_name.to_string(),
    };
    install.principals.push(principal.clone());
    save_install(config_dir, &install)?;
    Ok(principal)
}

pub fn pin_server(
    config_dir: &Path,
    tenant_id: &str,
    presented: &PresentedServer,
    replace: bool,
) -> Result<ServerPin, ConfigError> {
    reconcile_server(config_dir, tenant_id, presented, true, replace)
}

/// Merges a presented server key with the pin.
///
/// `explicit` is the `pin` command. Otherwise a missing pin is filled only when
/// `presented.trust_on_first_use` is set. A different key is refused unless
/// `replace` is set.
pub fn reconcile_server(
    config_dir: &Path,
    tenant_id: &str,
    presented: &PresentedServer,
    explicit: bool,
    replace: bool,
) -> Result<ServerPin, ConfigError> {
    let mut install = load_install(config_dir, tenant_id)?;
    let changed = apply_pin(&mut install.server, presented, explicit, replace)?;
    if changed {
        save_install(config_dir, &install)?;
    }
    Ok(install.server)
}

pub fn load_install(config_dir: &Path, tenant_id: &str) -> Result<InstallConfig, ConfigError> {
    if !is_tenant_id(tenant_id) {
        return Err(ConfigError::Tenant);
    }
    let path = install_path(config_dir, tenant_id);
    if !path.exists() {
        return Err(ConfigError::NotFound);
    }
    crate::util::ensure_private(&path).map_err(|_| ConfigError::Corrupt)?;
    let install: InstallConfig =
        serde_json::from_slice(&std::fs::read(&path)?).map_err(|_| ConfigError::Corrupt)?;
    if install.schema != INSTALL_SCHEMA || install.tenant_id != tenant_id {
        return Err(ConfigError::Corrupt);
    }
    Ok(install)
}

pub fn registration_bundle(
    config_dir: &Path,
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
    principal_id: Option<&str>,
) -> Result<RegistrationBundle, ConfigError> {
    let install = load_install(config_dir, tenant_id)?;
    let principal_id = match principal_id {
        Some(id) => id.to_string(),
        None if install.principals.len() == 1 => install.principals[0].principal_id.clone(),
        None => return Err(ConfigError::Missing("principal")),
    };
    if !install
        .principals
        .iter()
        .any(|p| p.principal_id == principal_id)
    {
        return Err(ConfigError::Principal);
    }
    let key = key::load_agent_key(data_dir, tenant_id, agent_id)?;
    let retired = retired_records(data_dir, tenant_id, agent_id)?;
    let mut retired_key_ids = Vec::new();
    let mut revoked_key_ids = Vec::new();
    for record in retired {
        match record.status.as_str() {
            STATUS_REVOKED => revoked_key_ids.push(record.key_id),
            STATUS_RETIRED => retired_key_ids.push(record.key_id),
            _ => retired_key_ids.push(record.key_id),
        }
    }
    Ok(RegistrationBundle {
        schema: REGISTER_SCHEMA.to_string(),
        tenant_id: tenant_id.to_string(),
        principal_id,
        principals: install.principals,
        actor: key.actor().to_string(),
        key_id: key.key_id().to_string(),
        ed25519_public_key: b64::encode(key.ed25519_public()),
        x25519_public_key: b64::encode(key.x25519_public()),
        retired_key_ids,
        revoked_key_ids,
    })
}

pub fn client_config_from_env(
    tenant_id: String,
    agent_id: String,
    principal_id: Option<String>,
    config_dir: PathBuf,
    data_dir: PathBuf,
) -> Result<ClientConfig, ConfigError> {
    if !is_tenant_id(&tenant_id) {
        return Err(ConfigError::Tenant);
    }
    let install = load_install(&config_dir, &tenant_id)?;
    let principal_id = match principal_id.filter(|s| !s.is_empty()) {
        Some(id) => id,
        None if install.principals.len() == 1 => install.principals[0].principal_id.clone(),
        None => return Err(ConfigError::Missing("CERVEAU_PRINCIPAL")),
    };
    if !is_principal_id(&principal_id)
        || !install
            .principals
            .iter()
            .any(|p| p.principal_id == principal_id)
    {
        return Err(ConfigError::Principal);
    }
    let presented = PresentedServer {
        endpoint: optional_endpoint()?,
        recipient_key_id: nonempty("CERVEAU_RECIPIENT_KEY_ID"),
        recipient_public: optional_key("CERVEAU_RECIPIENT_PUBLIC_KEY")?,
        signing_key_id: nonempty("CERVEAU_SIGNING_KEY_ID"),
        signing_public: optional_key("CERVEAU_SIGNING_PUBLIC_KEY")?,
        trust_on_first_use: nonempty("CERVEAU_TRUST_ON_FIRST_USE").as_deref() == Some("1"),
    };
    let _server = reconcile_server(&config_dir, &tenant_id, &presented, false, false)?;
    let install = load_install(&config_dir, &tenant_id)?;
    let recipient_key_id = install
        .server
        .recipient_key_id
        .clone()
        .ok_or(ConfigError::ServerUnpinned)?;
    let recipient_public = decode_pin(install.server.recipient_public_key.as_deref())?;
    let (signing_key_id, signing_public) = match (
        install.server.signing_key_id.clone(),
        install.server.signing_public_key.as_deref(),
    ) {
        (Some(id), Some(raw)) => (
            Some(id),
            Some(b64::decode_array(raw).map_err(|_| ConfigError::PublicKey)?),
        ),
        (None, None) => (None, None),
        _ => return Err(ConfigError::Corrupt),
    };
    let tool_name = install
        .server
        .tool_name
        .clone()
        .or_else(|| nonempty("CERVEAU_TOOL"))
        .unwrap_or_else(|| DEFAULT_TOOL.to_string());
    if tool_name.len() > 64 || !tool_name.chars().all(|c| c.is_ascii_graphic() && c != ' ') {
        return Err(ConfigError::Tool);
    }
    Ok(ClientConfig {
        config_dir,
        data_dir,
        tenant_id,
        agent_id,
        principal_id: principal_id.clone(),
        principals: install
            .principals
            .into_iter()
            .map(|p| p.principal_id)
            .collect(),
        recipient_key_id,
        recipient_public,
        signing_key_id,
        signing_public,
        endpoint: presented.endpoint.or(install.server.endpoint),
        tool_name,
        authorization: nonempty("CERVEAU_MCP_AUTHORIZATION"),
        session_id: nonempty("CERVEAU_MCP_SESSION_ID"),
        log_stderr: true,
    })
}

fn optional_key(name: &'static str) -> Result<Option<[u8; 32]>, ConfigError> {
    if nonempty(name).is_none() {
        return Ok(None);
    }
    decode_env_key(name).map(Some)
}

fn apply_pin(
    stored: &mut ServerPin,
    presented: &PresentedServer,
    explicit: bool,
    replace: bool,
) -> Result<bool, ConfigError> {
    let mut changed = false;
    if explicit {
        if let Some(url) = &presented.endpoint {
            let url = crate::client::validate_endpoint(url)?;
            if stored.endpoint.as_deref() != Some(url.as_str()) {
                stored.endpoint = Some(url);
                changed = true;
            }
        }
    }
    changed |= pin_material(
        &mut stored.recipient_key_id,
        &mut stored.recipient_public_key,
        PinChoice {
            presented_id: presented.recipient_key_id.as_deref(),
            presented_key: presented.recipient_public.as_ref(),
            explicit,
            tofu: presented.trust_on_first_use,
            replace,
            required_pair: true,
        },
    )?;
    changed |= pin_material(
        &mut stored.signing_key_id,
        &mut stored.signing_public_key,
        PinChoice {
            presented_id: presented.signing_key_id.as_deref(),
            presented_key: presented.signing_public.as_ref(),
            explicit,
            tofu: presented.trust_on_first_use,
            replace,
            required_pair: false,
        },
    )?;
    check_pin_shape(stored)?;
    Ok(changed)
}

struct PinChoice<'a> {
    presented_id: Option<&'a str>,
    presented_key: Option<&'a [u8; 32]>,
    explicit: bool,
    tofu: bool,
    replace: bool,
    required_pair: bool,
}

fn pin_material(
    stored_id: &mut Option<String>,
    stored_key: &mut Option<String>,
    choice: PinChoice<'_>,
) -> Result<bool, ConfigError> {
    match (choice.presented_id, choice.presented_key) {
        (None, None) => {
            if choice.explicit && choice.required_pair && stored_id.is_none() {
                return Err(ConfigError::ServerUnpinned);
            }
            Ok(false)
        }
        (Some(id), Some(key)) => {
            if !is_key_id(id) {
                return Err(ConfigError::KeyId);
            }
            let encoded = b64::encode(key);
            if let (Some(old_id), Some(old_key)) = (stored_id.as_deref(), stored_key.as_deref()) {
                if old_id != id || old_key != encoded {
                    if !choice.replace {
                        return Err(ConfigError::ServerKeyMismatch);
                    }
                } else {
                    return Ok(false);
                }
            } else if !choice.explicit && !choice.tofu {
                return Err(ConfigError::ServerUnpinned);
            }
            *stored_id = Some(id.to_string());
            *stored_key = Some(encoded);
            Ok(true)
        }
        _ => Err(ConfigError::Corrupt),
    }
}

fn check_pin_shape(server: &ServerPin) -> Result<(), ConfigError> {
    match (
        server.recipient_key_id.as_deref(),
        server.recipient_public_key.as_deref(),
    ) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => return Err(ConfigError::Corrupt),
    }
    if let Some(id) = &server.recipient_key_id {
        if !is_key_id(id) {
            return Err(ConfigError::KeyId);
        }
    }
    if let Some(raw) = &server.recipient_public_key {
        let bytes: [u8; 32] = b64::decode_array(raw).map_err(|_| ConfigError::PublicKey)?;
        let _ = bytes;
    }
    match (
        server.signing_key_id.as_deref(),
        server.signing_public_key.as_deref(),
    ) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => return Err(ConfigError::Corrupt),
    }
    if let Some(id) = &server.signing_key_id {
        if !is_key_id(id) {
            return Err(ConfigError::KeyId);
        }
    }
    Ok(())
}

fn decode_pin(raw: Option<&str>) -> Result<[u8; 32], ConfigError> {
    let raw = raw.ok_or(ConfigError::ServerUnpinned)?;
    b64::decode_array(raw).map_err(|_| ConfigError::PublicKey)
}

fn validate_identity(
    tenant_id: &str,
    principal_id: &str,
    display_name: &str,
) -> Result<(), ConfigError> {
    if !is_tenant_id(tenant_id) {
        return Err(ConfigError::Tenant);
    }
    if !is_principal_id(principal_id) {
        return Err(ConfigError::Principal);
    }
    let name = display_name.trim();
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(|c| c.is_control()) {
        return Err(ConfigError::DisplayName);
    }
    Ok(())
}

fn install_path(config_dir: &Path, tenant_id: &str) -> PathBuf {
    config_dir
        .join("tenants")
        .join(tenant_id)
        .join("install.json")
}

fn save_install(config_dir: &Path, install: &InstallConfig) -> Result<(), ConfigError> {
    let path = install_path(config_dir, &install.tenant_id);
    if let Some(parent) = path.parent() {
        util::ensure_dir(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(install).map_err(|_| ConfigError::Corrupt)?;
    bytes.push(b'\n');
    util::write_durable(path.parent().unwrap(), "install.json", &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::RunInput;
    use crate::client::Client;
    use crate::key::{generate_agent_key, load_agent_key};
    use crate::transport::Transport;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn recipient() -> [u8; 32] {
        PublicKey::from(&StaticSecret::from([9u8; 32])).to_bytes()
    }

    fn scratch() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "cerveau-install-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        let config = root.join("config");
        let data = root.join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        (config, data)
    }

    fn init_pair(config: &Path, data: &Path, tenant: &str, agent: &str) {
        init_install(InitRequest {
            config_dir: config.to_path_buf(),
            data_dir: data.to_path_buf(),
            tenant_id: tenant.into(),
            principal_id: "p_owner".into(),
            display_name: "Owner Display".into(),
            agent_id: agent.into(),
            endpoint: None,
            recipient_key_id: Some("cerveau-test".into()),
            recipient_public: Some(recipient()),
            signing_key_id: None,
            signing_public: None,
            tool_name: None,
        })
        .unwrap();
    }

    #[test]
    fn two_tenants_keep_separate_keys_queues_and_sequences() {
        let (config, data) = scratch();
        init_pair(&config, &data, "tenant-a", "agent-a");
        init_pair(&config, &data, "tenant-b", "agent-b");
        generate_agent_key(&data, "tenant-a", "agent-a2").unwrap();
        let key_a = load_agent_key(&data, "tenant-a", "agent-a").unwrap();
        let key_b = load_agent_key(&data, "tenant-b", "agent-b").unwrap();
        let key_a2 = load_agent_key(&data, "tenant-a", "agent-a2").unwrap();
        assert_ne!(key_a.key_id(), key_b.key_id());
        assert_ne!(key_a.key_id(), key_a2.key_id());
        assert!(key_a.key_id().contains("tenant-a"));
        assert!(key_b.key_id().contains("tenant-b"));
        assert_eq!(key_a.actor(), "gb:tenant-a:agent-a");
        assert_eq!(key_a2.actor(), "gb:tenant-a:agent-a2");

        let recip = recipient();
        let mut cfg_a = client_config_from_parts(&config, &data, "tenant-a", "agent-a", recip);
        cfg_a.log_stderr = false;
        let mut cfg_b = client_config_from_parts(&config, &data, "tenant-b", "agent-b", recip);
        cfg_b.log_stderr = false;

        let fail = FailTransport;
        let client_a = Client::with_transport(cfg_a, fail);
        let report_a = client_a
            .run(RunInput {
                principal_id: "p_owner".into(),
                transcript: "marker-tenant-a".into(),
                ..RunInput::default()
            })
            .unwrap();
        assert_eq!(report_a.seq, 1);
        let report_a2 = client_a
            .run(RunInput {
                principal_id: "p_owner".into(),
                transcript: "marker-tenant-a-2".into(),
                ..RunInput::default()
            })
            .unwrap();
        assert_eq!(report_a2.seq, 2);

        let client_b = Client::with_transport(
            client_config_from_parts(&config, &data, "tenant-b", "agent-b", recip),
            FailTransport,
        );
        let report_b = client_b
            .run(RunInput {
                principal_id: "p_owner".into(),
                transcript: "marker-tenant-b".into(),
                ..RunInput::default()
            })
            .unwrap();
        assert_eq!(report_b.seq, 1);
        let status_b = crate::client::queue_status(&data, "tenant-b", "agent-b").unwrap();
        assert_eq!(status_b.seqs, vec![1]);
        let status_a = crate::client::queue_status(&data, "tenant-a", "agent-a").unwrap();
        assert_eq!(status_a.seqs, vec![1, 2]);
        let bytes_b = std::fs::read(
            key::agent_dir(&data, "tenant-b", "agent-b")
                .unwrap()
                .join("queue.q"),
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&bytes_b).contains("marker-tenant-a"));
        let _ = std::fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn server_key_pin_refuses_a_mismatch_and_accepts_first_use() {
        let (config, data) = scratch();
        init_install(InitRequest {
            config_dir: config.clone(),
            data_dir: data.clone(),
            tenant_id: "tenant-test".into(),
            principal_id: "p_owner".into(),
            display_name: "Owner Display".into(),
            agent_id: "agent-test".into(),
            endpoint: Some("https://cerveau.example/mcp".into()),
            recipient_key_id: None,
            recipient_public: None,
            signing_key_id: None,
            signing_public: None,
            tool_name: None,
        })
        .unwrap();
        let key_a = recipient();
        let key_b = PublicKey::from(&StaticSecret::from([8u8; 32])).to_bytes();
        let unpinned = reconcile_server(
            &config,
            "tenant-test",
            &PresentedServer {
                endpoint: None,
                recipient_key_id: Some("backend-a".into()),
                recipient_public: Some(key_a),
                signing_key_id: None,
                signing_public: None,
                trust_on_first_use: false,
            },
            false,
            false,
        );
        assert!(matches!(unpinned, Err(ConfigError::ServerUnpinned)));
        reconcile_server(
            &config,
            "tenant-test",
            &PresentedServer {
                endpoint: None,
                recipient_key_id: Some("backend-a".into()),
                recipient_public: Some(key_a),
                signing_key_id: None,
                signing_public: None,
                trust_on_first_use: true,
            },
            false,
            false,
        )
        .unwrap();
        let mismatch = pin_server(
            &config,
            "tenant-test",
            &PresentedServer {
                endpoint: None,
                recipient_key_id: Some("backend-b".into()),
                recipient_public: Some(key_b),
                signing_key_id: None,
                signing_public: None,
                trust_on_first_use: true,
            },
            false,
        );
        assert!(matches!(mismatch, Err(ConfigError::ServerKeyMismatch)));
        let _ = std::fs::remove_dir_all(config.parent().unwrap());
    }

    struct FailTransport;
    impl Transport for FailTransport {
        fn call(
            &self,
            _: &crate::seal::RunMessage,
            _: std::time::Duration,
        ) -> Result<crate::transport::CallOutcome, crate::transport::TransportError> {
            Err(crate::transport::TransportError::Timeout)
        }
    }

    fn client_config_from_parts(
        config: &Path,
        data: &Path,
        tenant: &str,
        agent: &str,
        recipient: [u8; 32],
    ) -> ClientConfig {
        let _ = config;
        ClientConfig {
            config_dir: config.to_path_buf(),
            data_dir: data.to_path_buf(),
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            principal_id: "p_owner".into(),
            principals: vec!["p_owner".into()],
            recipient_key_id: "cerveau-test".into(),
            recipient_public: recipient,
            signing_key_id: None,
            signing_public: None,
            endpoint: None,
            tool_name: DEFAULT_TOOL.into(),
            authorization: None,
            session_id: None,
            log_stderr: false,
        }
    }
}
