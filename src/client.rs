use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

use crate::account::{self, AccountError, AccountKey};
use crate::body::{self, prepare_body, RunInput};
use crate::envelope::{validate_envelope, EnvelopeStatus, TurnContext, VerifyConfig};
use crate::id::{self, may_send_direct};
use crate::key::{self, load_agent_key, load_queue_state, KeyError};
use crate::queue::{new_run_id, QueueError, QueueState, QueuedRun};
use crate::seal::{seal_run, RunMessage, SealError, SealRequest};
use crate::transport::{CallOutcome, HttpTransport, Transport, TransportError};
use crate::util::{self, now_rfc3339};

/// Hard timeout of one `cerveau.run` RPC.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_TOOL: &str = "cerveau.run";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("recipient or signing key id is not [A-Za-z0-9_-]")]
    KeyId,
    #[error("public key must be 32 bytes, base64")]
    PublicKey,
    #[error("CERVEAU_MCP_URL must be http or https and must not embed userinfo")]
    Endpoint,
    #[error("tool name is empty or too long")]
    Tool,
    #[error("tenant id is not an ASCII token of [A-Za-z0-9_-]")]
    Tenant,
    #[error("principal id is not an ASCII token of [A-Za-z0-9_-]")]
    Principal,
    #[error("display name is empty or contains control characters")]
    DisplayName,
    #[error("this install is already initialized")]
    AlreadyInitialized,
    #[error("install was not found")]
    NotFound,
    #[error("the pinned server key does not match the one presented")]
    ServerKeyMismatch,
    #[error(
        "the server key is not pinned; pass it to init or pin, or set CERVEAU_TRUST_ON_FIRST_USE=1"
    )]
    ServerUnpinned,
    #[error("install file is inconsistent")]
    Corrupt,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("key: {0}")]
    Key(#[from] KeyError),
}

#[derive(Clone)]
pub struct ClientConfig {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub tenant_id: String,
    pub agent_id: String,
    pub principal_id: String,
    pub principals: Vec<String>,
    pub recipient_key_id: String,
    pub recipient_public: [u8; 32],
    pub signing_key_id: Option<String>,
    pub signing_public: Option<[u8; 32]>,
    pub endpoint: Option<String>,
    pub tool_name: String,
    pub authorization: Option<String>,
    pub session_id: Option<String>,
    pub log_stderr: bool,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("config_dir", &self.config_dir)
            .field("data_dir", &self.data_dir)
            .field("tenant_id", &self.tenant_id)
            .field("agent_id", &self.agent_id)
            .field("principal_id", &self.principal_id)
            .field("recipient_key_id", &self.recipient_key_id)
            .field("signing_key_id", &self.signing_key_id)
            .field("endpoint", &self.endpoint)
            .field("tool_name", &self.tool_name)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "session_id",
                &self.session_id.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl ClientConfig {
    pub fn from_env(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        principal_id: Option<String>,
        config_dir: PathBuf,
        data_dir: PathBuf,
    ) -> Result<Self, ConfigError> {
        crate::install::client_config_from_env(
            tenant_id.into(),
            agent_id.into(),
            principal_id,
            config_dir,
            data_dir,
        )
    }
}

pub(crate) fn required(name: &'static str) -> Result<String, ConfigError> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(ConfigError::Missing(name)),
    }
}

pub(crate) fn nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub(crate) fn decode_env_key(name: &'static str) -> Result<[u8; 32], ConfigError> {
    let raw = required(name)?;
    crate::b64::decode_array(raw.trim()).map_err(|_| ConfigError::PublicKey)
}

pub(crate) fn optional_endpoint() -> Result<Option<String>, ConfigError> {
    match std::env::var("CERVEAU_MCP_URL") {
        Ok(value) if !value.trim().is_empty() => Ok(Some(validate_endpoint(value.trim())?)),
        _ => Ok(None),
    }
}

pub fn validate_endpoint(url: &str) -> Result<String, ConfigError> {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(ConfigError::Endpoint);
    }
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or("");
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') {
        return Err(ConfigError::Endpoint);
    }
    Ok(url.to_string())
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("agent key: {0}")]
    Key(#[from] KeyError),
    #[error("attribution: {0}")]
    Attribution(#[from] body::AttributionError),
    #[error("seal: {0}")]
    Seal(#[from] SealError),
    #[error("queue: {0}")]
    Queue(#[from] QueueError),
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("sequence space is exhausted")]
    Seq,
    #[error("run_id is not [A-Za-z0-9_-] within the length bound")]
    RunId,
    #[error("principal is not configured for this install")]
    Principal,
    #[error("account key: {0}")]
    Account(#[from] AccountError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissReason {
    Timeout,
    Unreachable,
    Http { status: u16 },
    Rpc,
    MissingEnvelope,
    InvalidEnvelope,
    StaleEnvelope,
    EndpointUnset,
    Duplicate,
    QueuedBehind,
}

impl MissReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::Http { .. } => "http",
            Self::Rpc => "rpc",
            Self::MissingEnvelope => "missing_envelope",
            Self::InvalidEnvelope => "invalid_envelope",
            Self::StaleEnvelope => "stale_envelope",
            Self::EndpointUnset => "endpoint_unset",
            Self::Duplicate => "duplicate",
            Self::QueuedBehind => "queued_behind",
        }
    }
}

impl From<TransportError> for MissReason {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::Timeout => Self::Timeout,
            TransportError::Unreachable => Self::Unreachable,
            TransportError::EndpointUnset => Self::EndpointUnset,
            TransportError::Http(status) => Self::Http { status },
            TransportError::Rpc | TransportError::Protocol => Self::Rpc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Envelope(TurnContext),
    NoEnvelope { reason: MissReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub run_id: String,
    pub seq: u64,
    pub queued: bool,
    pub flushed: u64,
    pub outcome: RunOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub flushed: u64,
    pub remaining: u64,
    pub stopped: Option<MissReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueStatus {
    pub pending: u64,
    pub seqs: Vec<u64>,
    pub run_ids: Vec<String>,
}

pub struct Client<T: Transport> {
    config: ClientConfig,
    transport: Arc<T>,
}

impl Client<HttpTransport> {
    pub fn new(config: ClientConfig) -> Self {
        let transport = HttpTransport::new(
            config.endpoint.clone(),
            config.tool_name.clone(),
            config.authorization.clone(),
            config.session_id.clone(),
        );
        Self::with_transport(config, transport)
    }
}

impl<T: Transport + 'static> Client<T> {
    pub fn with_transport(config: ClientConfig, transport: T) -> Self {
        Self {
            config,
            transport: Arc::new(transport),
        }
    }

    /// Seals this turn and calls Cerveau.
    ///
    /// Every older queued run is replayed, in increasing `seq`, before this
    /// turn is sent with `replay: false`. If an older run is still queued, the
    /// new run is not sent. Each RPC uses [`CALL_TIMEOUT`]. Envelopes returned
    /// for replayed runs are ignored.
    pub fn run(&self, mut input: RunInput) -> Result<RunReport, ClientError> {
        let key = load_agent_key(
            &self.config.data_dir,
            &self.config.tenant_id,
            &self.config.agent_id,
        )?;
        if input.principal_id.is_empty() {
            input.principal_id = self.config.principal_id.clone();
        }
        if !self
            .config
            .principals
            .iter()
            .any(|id| id == &input.principal_id)
        {
            return Err(ClientError::Principal);
        }
        input.tenant_id = self.config.tenant_id.clone();
        let (store, mut state) = load_queue_state(&self.config.data_dir, &key)?;
        if state.next_seq == 0 || state.next_seq == u64::MAX {
            return Err(ClientError::Seq);
        }
        let seq = state.next_seq;
        let run_id = new_run_id()?;
        let sent_at = now_rfc3339();
        let principal_id = input.principal_id.clone();
        let body = prepare_body(input)?;
        state.records.push(QueuedRun {
            run_id: run_id.clone(),
            seq,
            sent_at,
            principal_id,
            body,
        });
        state.next_seq = seq + 1;
        state.records.sort_by_key(|record| record.seq);
        store.store(&key, &state)?;

        let dir = key::agent_dir(
            &self.config.data_dir,
            &self.config.tenant_id,
            &self.config.agent_id,
        )?;
        let drained = self.drain(&store, &key, state, Some(run_id.clone()), &dir)?;
        let queued = drained.ids.iter().any(|id| id == &run_id);
        let outcome = match drained.live {
            Live::Finished(outcome) => outcome,
            Live::Pending => RunOutcome::NoEnvelope {
                reason: drained.stopped.unwrap_or(MissReason::QueuedBehind),
            },
        };
        Ok(RunReport {
            run_id,
            seq,
            queued,
            flushed: drained.flushed,
            outcome,
        })
    }

    /// Replays the whole queue in `seq` order. Every send uses `replay: true`.
    /// Each RPC has its own 2 second timeout. Returned envelopes are ignored.
    pub fn replay(&self) -> Result<ReplayReport, ClientError> {
        let key = load_agent_key(
            &self.config.data_dir,
            &self.config.tenant_id,
            &self.config.agent_id,
        )?;
        let dir = key::agent_dir(
            &self.config.data_dir,
            &self.config.tenant_id,
            &self.config.agent_id,
        )?;
        let (store, state) = load_queue_state(&self.config.data_dir, &key)?;
        let drained = self.drain(&store, &key, state, None, &dir)?;
        Ok(ReplayReport {
            flushed: drained.flushed,
            remaining: drained.ids.len() as u64,
            stopped: drained.stopped,
        })
    }

    fn drain(
        &self,
        store: &crate::queue::QueueStore,
        key: &key::AgentKey,
        mut state: QueueState,
        live_id: Option<String>,
        dir: &Path,
    ) -> Result<Drain, ClientError> {
        state.records.sort_by_key(|record| record.seq);
        let mut flushed = 0u64;
        let mut live = Live::Pending;
        let mut stopped = None;

        while !state.records.is_empty() && stopped.is_none() && !matches!(live, Live::Finished(_)) {
            let seqs: Vec<u64> = state.records.iter().map(|record| record.seq).collect();
            let front_seq = state.records[0].seq;
            let front_id = state.records[0].run_id.clone();
            let direct = live_id.as_deref() == Some(front_id.as_str());
            if direct && !may_send_direct(&seqs, front_seq) {
                self.note_miss(dir, &front_id, front_seq, &MissReason::QueuedBehind);
                stopped = Some(MissReason::QueuedBehind);
                break;
            }
            let record = state.records[0].clone();
            let wire = self.seal_queued(key, &record, !direct)?;
            if !wire.replay && !may_send_direct(&seqs, wire.seq) {
                self.note_miss(dir, &wire.run_id, wire.seq, &MissReason::QueuedBehind);
                stopped = Some(MissReason::QueuedBehind);
                break;
            }
            match self.dispatch(&wire) {
                Ok(outcome) => {
                    state.records.remove(0);
                    store.store(key, &state)?;
                    if direct {
                        live = Live::Finished(self.interpret(outcome, key));
                    } else {
                        flushed += 1;
                    }
                }
                Err(reason) => {
                    self.note_miss(dir, &wire.run_id, wire.seq, &reason);
                    if direct {
                        live = Live::Finished(RunOutcome::NoEnvelope {
                            reason: reason.clone(),
                        });
                    }
                    stopped = Some(reason);
                }
            }
        }

        if matches!(live, Live::Pending) {
            if let Some(id) = &live_id {
                if let Some(record) = state.records.iter().find(|record| &record.run_id == id) {
                    self.note_miss(dir, &record.run_id, record.seq, &MissReason::QueuedBehind);
                }
            }
        }

        Ok(Drain {
            flushed,
            stopped,
            live,
            ids: state
                .records
                .into_iter()
                .map(|record| record.run_id)
                .collect(),
        })
    }

    fn interpret(&self, outcome: CallOutcome, key: &key::AgentKey) -> RunOutcome {
        if outcome.duplicate {
            return RunOutcome::NoEnvelope {
                reason: MissReason::Duplicate,
            };
        }
        let Some(envelope) = outcome.envelope else {
            return RunOutcome::NoEnvelope {
                reason: MissReason::MissingEnvelope,
            };
        };
        let (Some(signing_key_id), Some(signing_public)) = (
            self.config.signing_key_id.clone(),
            self.config.signing_public,
        ) else {
            return RunOutcome::NoEnvelope {
                reason: MissReason::InvalidEnvelope,
            };
        };
        let cfg = VerifyConfig {
            signing_key_id,
            signing_public,
            expected_actor: Some(key.actor().to_string()),
        };
        match validate_envelope(&envelope, &cfg, Utc::now()) {
            EnvelopeStatus::Fresh(ctx) => RunOutcome::Envelope(ctx),
            EnvelopeStatus::Stale(_) => RunOutcome::NoEnvelope {
                reason: MissReason::StaleEnvelope,
            },
            EnvelopeStatus::Rejected { .. } => RunOutcome::NoEnvelope {
                reason: MissReason::InvalidEnvelope,
            },
        }
    }

    fn seal_queued(
        &self,
        key: &key::AgentKey,
        record: &QueuedRun,
        replay: bool,
    ) -> Result<RunMessage, ClientError> {
        let account = self.account_key(&record.principal_id)?;
        Ok(seal_run(SealRequest {
            body: &record.body,
            tenant_id: &self.config.tenant_id,
            principal_id: &record.principal_id,
            run_id: &record.run_id,
            seq: record.seq,
            sent_at: &record.sent_at,
            replay,
            agent: key,
            recipient_key_id: &self.config.recipient_key_id,
            recipient_public: &self.config.recipient_public,
            randomness: None,
            account: account.as_ref(),
        })?)
    }

    /// Charge la clé du compte de ce user id. Absente : pas de preuve.
    fn account_key(&self, user_id: &str) -> Result<Option<AccountKey>, ClientError> {
        match account::load_account_key(&self.config.data_dir, &self.config.tenant_id, user_id) {
            Ok(key) => Ok(Some(key)),
            Err(AccountError::NotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn dispatch(&self, message: &RunMessage) -> Result<CallOutcome, MissReason> {
        let timeout = CALL_TIMEOUT;
        let transport = Arc::clone(&self.transport);
        let message = message.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = transport.call(&message, timeout);
            let _ = tx.send(result);
        });
        match rx.recv_timeout(timeout) {
            Ok(result) => result.map_err(MissReason::from),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(MissReason::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(MissReason::Unreachable),
        }
    }

    fn note_miss(&self, dir: &Path, run_id: &str, seq: u64, reason: &MissReason) {
        let shown = if id::is_run_id(run_id) {
            run_id
        } else {
            "invalid"
        };
        let line = format!(
            "ts={} agent={} run_id={shown} seq={seq} reason={}",
            now_rfc3339(),
            self.config.agent_id,
            reason.as_str()
        );
        if self.config.log_stderr {
            eprintln!("cerveau: {line}");
        }
        if let Err(err) = util::append_private_line(&dir.join("miss.log"), &line) {
            if self.config.log_stderr {
                eprintln!("cerveau: miss log: {err}");
            }
        }
    }
}

struct Drain {
    flushed: u64,
    stopped: Option<MissReason>,
    live: Live,
    ids: Vec<String>,
}

enum Live {
    Pending,
    Finished(RunOutcome),
}

pub fn queue_status(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
) -> Result<QueueStatus, ClientError> {
    let key = load_agent_key(data_dir, tenant_id, agent_id)?;
    let (_store, state) = load_queue_state(data_dir, &key)?;
    Ok(QueueStatus {
        pending: state.records.len() as u64,
        seqs: state.records.iter().map(|record| record.seq).collect(),
        run_ids: state
            .records
            .iter()
            .map(|record| record.run_id.clone())
            .collect(),
    })
}

pub fn queue_drop(
    data_dir: &Path,
    tenant_id: &str,
    agent_id: &str,
    run_id: &str,
) -> Result<bool, ClientError> {
    if !id::is_run_id(run_id) {
        return Err(ClientError::RunId);
    }
    let key = load_agent_key(data_dir, tenant_id, agent_id)?;
    let (store, mut state) = load_queue_state(data_dir, &key)?;
    let before = state.records.len();
    state.records.retain(|record| record.run_id != run_id);
    let removed = state.records.len() != before;
    if removed {
        store.store(&key, &state)?;
    }
    Ok(removed)
}

pub fn report_json(report: &RunReport) -> Value {
    let mut value = serde_json::json!({
        "run_id": report.run_id,
        "seq": report.seq,
        "queued": report.queued,
        "flushed": report.flushed,
    });
    match &report.outcome {
        RunOutcome::Envelope(ctx) => {
            value["outcome"] = Value::String("envelope".into());
            value["context"] = ctx.snapshot();
        }
        RunOutcome::NoEnvelope { reason } => {
            value["outcome"] = Value::String("no_envelope".into());
            value["reason"] = Value::String(reason.as_str().into());
            if let MissReason::Http { status } = reason {
                value["http_status"] = Value::from(*status);
            }
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::{MessageOrigin, TurnMessage};
    use crate::envelope;
    use crate::key::generate_agent_key;
    use ed25519_dalek::SigningKey;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use x25519_dalek::{PublicKey, StaticSecret};

    struct Script {
        plan: Mutex<VecDeque<bool>>,
        log: Mutex<Vec<Rec>>,
        signing_seed: [u8; 32],
    }

    #[derive(Clone)]
    struct Rec {
        seq: u64,
        run_id: String,
        replay: bool,
        ok: bool,
        wire: String,
    }

    impl Transport for Script {
        fn call(
            &self,
            message: &RunMessage,
            timeout: Duration,
        ) -> Result<CallOutcome, TransportError> {
            assert_eq!(timeout, CALL_TIMEOUT);
            let ok = self.plan.lock().expect("plan").pop_front().unwrap_or(false);
            let wire = serde_json::to_string(message).unwrap();
            self.log.lock().expect("log").push(Rec {
                seq: message.seq,
                run_id: message.run_id.clone(),
                replay: message.replay,
                ok,
                wire,
            });
            if !ok {
                return Err(TransportError::Timeout);
            }
            let envelope = envelope::sample_envelope(
                &message.run_id,
                &message.agent.actor,
                &self.signing_seed,
                "cerveau-test",
                &now_rfc3339(),
            )
            .unwrap();
            Ok(CallOutcome {
                envelope: Some(envelope),
                duplicate: false,
            })
        }
    }

    struct Harness {
        home: PathBuf,
        signing_seed: [u8; 32],
        recipient_public: [u8; 32],
    }

    impl Harness {
        fn new() -> Self {
            let home = std::env::temp_dir().join(format!(
                "cerveau-client-{}-{}",
                std::process::id(),
                ulid::Ulid::new()
            ));
            std::fs::create_dir_all(&home).unwrap();
            generate_agent_key(&home, "tenant-test", "agent-test").unwrap();
            let signing_seed = [5u8; 32];
            let recipient = StaticSecret::from([6u8; 32]);
            Self {
                home,
                signing_seed,
                recipient_public: PublicKey::from(&recipient).to_bytes(),
            }
        }

        fn config(&self) -> ClientConfig {
            let signing = SigningKey::from_bytes(&self.signing_seed);
            ClientConfig {
                config_dir: self.home.clone(),
                data_dir: self.home.clone(),
                tenant_id: "tenant-test".into(),
                agent_id: "agent-test".into(),
                principal_id: "p_owner".into(),
                principals: vec!["p_owner".into()],
                recipient_key_id: "cerveau-test".into(),
                recipient_public: self.recipient_public,
                signing_key_id: Some("cerveau-test".into()),
                signing_public: Some(signing.verifying_key().to_bytes()),
                endpoint: None,
                tool_name: DEFAULT_TOOL.into(),
                authorization: Some("SecretBearerValue".into()),
                session_id: None,
                log_stderr: false,
            }
        }

        fn client(&self, plan: Vec<bool>) -> (Client<Script>, Arc<Script>) {
            let script = Script {
                plan: Mutex::new(plan.into()),
                log: Mutex::new(Vec::new()),
                signing_seed: self.signing_seed,
            };
            let arc = Arc::new(script);
            let client = Client {
                config: self.config(),
                transport: Arc::clone(&arc),
            };
            (client, arc)
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn input(text: &str) -> RunInput {
        RunInput {
            tenant_id: "tenant-test".into(),
            principal_id: "p_owner".into(),
            transcript: text.into(),
            messages: vec![TurnMessage {
                origin: MessageOrigin::Human { claimed_from: None },
                text: text.into(),
                ref_id: None,
                at: None,
            }],
            ..RunInput::default()
        }
    }

    fn assert_never_direct_while_older_pending(log: &[Rec]) {
        let mut pending = std::collections::BTreeSet::new();
        for call in log {
            if !call.replay {
                assert!(
                    pending.iter().all(|seq| *seq >= call.seq),
                    "sent seq {} direct while {:?} still pending",
                    call.seq,
                    pending
                );
            }
            if call.ok {
                pending.remove(&call.seq);
            } else {
                pending.insert(call.seq);
            }
        }
    }

    #[test]
    fn does_not_send_newer_direct_while_older_is_queued() {
        let harness = Harness::new();
        let (client, script) = harness.client(vec![false, false]);
        let first = client.run(input("un")).unwrap();
        assert!(matches!(
            first.outcome,
            RunOutcome::NoEnvelope {
                reason: MissReason::Timeout
            }
        ));
        assert!(first.queued);
        let second = client.run(input("deux")).unwrap();
        assert!(second.queued);
        assert!(second.seq > first.seq);
        let log = script.log.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, first.seq);
        assert!(!log[0].replay);
        assert!(!log[0].ok);
        assert_eq!(log[1].run_id, first.run_id);
        assert!(log[1].replay);
        assert!(!log[1].ok);
        assert!(log.iter().all(|call| call.run_id != second.run_id));
        assert_never_direct_while_older_pending(&log);
        let status = queue_status(&harness.home, "tenant-test", "agent-test").unwrap();
        assert_eq!(status.seqs, vec![first.seq, second.seq]);
        let miss = std::fs::read_to_string(
            key::agent_dir(&harness.home, "tenant-test", "agent-test")
                .unwrap()
                .join("miss.log"),
        )
        .unwrap();
        assert!(miss.contains("reason=timeout"));
        assert!(miss.contains("reason=queued_behind"));
        assert!(!miss.contains("PLAINTEXT"));
        assert!(!miss.contains("SecretBearerValue"));
        let debug = format!("{:?}", harness.config());
        assert!(!debug.contains("SecretBearerValue"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn drains_in_seq_order_before_the_direct_send_and_ignores_replay_envelopes() {
        let harness = Harness::new();
        let (client, script) = harness.client(vec![false, false, true, true, true]);
        let first = client.run(input("un")).unwrap();
        let second = client.run(input("deux")).unwrap();
        assert!(script
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|c| c.run_id != second.run_id));
        let third = client.run(input("trois")).unwrap();
        let log = script.log.lock().unwrap().clone();
        assert_never_direct_while_older_pending(&log);
        let tail = &log[log.len() - 3..];
        assert!(tail[0].replay && tail[0].seq == first.seq && tail[0].ok);
        assert!(tail[1].replay && tail[1].seq == second.seq && tail[1].ok);
        assert!(!tail[2].replay && tail[2].seq == third.seq && tail[2].ok);
        assert!(tail[0].seq < tail[1].seq && tail[1].seq < tail[2].seq);
        match third.outcome {
            RunOutcome::Envelope(ctx) => assert_eq!(ctx.run_id(), third.run_id),
            other => panic!("expected the live envelope, got {other:?}"),
        }
        assert!(!third.queued);
        assert_eq!(third.flushed, 2);
        assert_eq!(
            queue_status(&harness.home, "tenant-test", "agent-test")
                .unwrap()
                .pending,
            0
        );
        let marker = "PLAINTEXT_MARKER_9f3a";
        assert!(log.iter().all(|call| !call.wire.contains(marker)));
    }

    #[test]
    fn queue_file_survives_reopen_and_hides_plaintext() {
        let harness = Harness::new();
        let marker = "PLAINTEXT_MARKER_9f3a sk-abcdefghijklmnopqrstuvwxyz";
        let (client, _) = harness.client(vec![false]);
        client.run(input(marker)).unwrap();
        drop(client);
        let path = key::agent_dir(&harness.home, "tenant-test", "agent-test")
            .unwrap()
            .join("queue.q");
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"GBQ2"));
        assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
        assert!(!String::from_utf8_lossy(&bytes).contains("sk-abcdefghijklmnopqrstuvwxyz"));
        let (client, script) = harness.client(vec![true]);
        let report = client.replay().unwrap();
        assert_eq!(report.flushed, 1);
        assert_eq!(report.remaining, 0);
        let log = script.log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert!(log[0].replay);
        assert!(log[0].ok);
    }

    #[test]
    fn passes_the_two_second_timeout_to_the_transport() {
        let harness = Harness::new();
        let seen = Arc::new(Mutex::new(None));
        struct Share(Arc<Mutex<Option<Duration>>>);
        impl Transport for Share {
            fn call(
                &self,
                _: &RunMessage,
                timeout: Duration,
            ) -> Result<CallOutcome, TransportError> {
                *self.0.lock().unwrap() = Some(timeout);
                Err(TransportError::Timeout)
            }
        }
        let report = Client::with_transport(harness.config(), Share(Arc::clone(&seen)))
            .run(input("hello"))
            .unwrap();
        assert!(matches!(
            report.outcome,
            RunOutcome::NoEnvelope {
                reason: MissReason::Timeout
            }
        ));
        assert_eq!(*seen.lock().unwrap(), Some(CALL_TIMEOUT));
    }

    #[test]
    fn account_sig_rides_the_wire_and_the_replay() {
        use std::os::unix::fs::PermissionsExt;

        let harness = Harness::new();
        let (client, script) = harness.client(vec![true]);
        client.run(input("sans")).unwrap();
        {
            let log = script.log.lock().unwrap();
            let wire: serde_json::Value = serde_json::from_str(&log[0].wire).unwrap();
            assert!(wire.get("account").is_none());
        }

        let public =
            crate::account::account_public(&harness.home, "tenant-test", "p_owner").unwrap();
        let pubkey: [u8; 32] = crate::b64::decode_array(&public.ed25519_public_key).unwrap();
        let (client, script) = harness.client(vec![false, true, true]);
        let queued = client.run(input("avec")).unwrap();
        assert!(queued.queued);
        let replayed = client.replay().unwrap();
        assert_eq!(replayed.flushed, 1);
        let direct = client.run(input("suite")).unwrap();
        assert!(!direct.queued);

        let log = script.log.lock().unwrap();
        assert_eq!(log.len(), 3);
        let mut sigs = Vec::new();
        for call in log.iter() {
            let message: RunMessage = serde_json::from_str(&call.wire).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&call.wire)
                .unwrap()
                .get("principal_id")
                .is_none());
            let account = message.account.as_ref().expect("account proof");
            assert_eq!(account.key_id, public.key_id);
            crate::seal::verify_account(&message, &pubkey).unwrap();
            sigs.push(account.sig.clone());
        }
        assert!(!log[0].replay && !log[0].ok);
        assert!(log[1].replay && log[1].ok);
        assert!(!log[2].replay && log[2].ok);
        assert_ne!(sigs[0], sigs[1]);

        let path = harness
            .home
            .join("tenants")
            .join("tenant-test")
            .join("accounts")
            .join("p_owner.json");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (client, script) = harness.client(vec![true]);
        let err = client.run(input("ouvert")).unwrap_err();
        assert!(matches!(
            err,
            ClientError::Account(AccountError::Permissions)
        ));
        assert!(script.log.lock().unwrap().is_empty());
    }
}
