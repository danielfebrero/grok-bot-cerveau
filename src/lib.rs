//! Box-side client for the EG MCP.
//!
//! [`context_turn`] speaks Streamable HTTP on `/mcp`: initialize, `tools/list`,
//! then `channel_thread` with `action = context`. The bearer stays in a mode
//! 0600 file and is never printed. The server maps that bearer to the account.
//! The returned context is read-only: it does not replace the agent's rules
//! or a human approval before a side effect.
//!
//! [`Client::run`] is the retired sealed `gb.run.v1` path, selected with
//! `--sealed`. Each installation then has its own tenant, a user key, and
//! agent keys. The client redacts secret spans, seals the filtered transcript,
//! and signs the ciphertext.
//!
//! Pending runs are replayed in `seq` order before any newer direct send.
//! A run N+1 is never sent with `replay: false` while run N is still queued.
//! `seq` belongs to the tenant and the agent. Key rotation keeps it.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("cerveau stores private keys with Unix mode 0600 and only builds on Unix");

mod account;
mod b64;
mod body;
mod canon;
mod client;
mod crypto;
mod envelope;
mod id;
mod install;
mod key;
mod mcp_eg;
mod queue;
mod redact;
mod seal;
mod transport;
mod util;

pub use account::{account_public, AccountError, AccountPublic, ACCOUNT_PUB_SCHEMA};
pub use body::{
    parse_message, parse_messages, prepare_body, AttributionError, Decision, MessageOrigin,
    RunBody, RunInput, ToolResult, TranscriptEntry, TurnMessage, BODY_SCHEMA,
};
pub use canon::canonical_json;
pub use client::{
    queue_drop, queue_status, report_json, validate_endpoint, Client, ClientConfig, ClientError,
    ConfigError, MissReason, QueueStatus, ReplayReport, RunOutcome, RunReport, CALL_TIMEOUT,
    DEFAULT_TOOL,
};
pub use envelope::{
    attach_integrity, sample_envelope, validate_envelope, EnvelopeError, EnvelopeStatus,
    RejectReason, TurnContext, VerifyConfig, ENVELOPE_BUILDER, ENVELOPE_TTL_SECONDS, TURN_SCHEMA,
};
pub use id::{
    is_key_id, is_run_id, is_tenant_id, is_token, is_user_id, AGENT_ID_MAX, KEY_ID_MAX, RUN_ID_MAX,
    TENANT_ID_MAX, USER_ID_MAX,
};
pub use install::{
    add_user, config_home, ensure_local, init_install, load_install, pin_server, reconcile_server,
    registration_bundle, InitRequest, InstallConfig, PresentedServer, RegistrationBundle,
    ServerPin, User, INSTALL_SCHEMA, REGISTER_SCHEMA,
};
pub use key::{
    agent_dir, data_home, generate_agent_key, load_agent_key, revoke_key, rotate_agent_key,
    AgentKey, KeyError, PublicExport, KEY_SCHEMA, PUB_SCHEMA, STATUS_ACTIVE, STATUS_RETIRED,
    STATUS_REVOKED,
};
pub use mcp_eg::{
    append_turn, context_turn, default_token_path, mcp_url, stable_ref, wants_mcp, EgError,
    TokenFile, TurnRequest, CALL_TIMEOUT as MCP_CALL_TIMEOUT, DEFAULT_CONVERSATION,
};
pub use redact::{redact_text, RedactOptions, Redaction};
pub use seal::{
    associated_data, hkdf_info, hkdf_salt, open_run, seal_run, signature_preimage, verify_account,
    AccountBlock, EncBlock, RunMessage, SealError, SealRandomness, SealRequest, SigBlock,
    RUN_SCHEMA, RUN_VERSION, SEAL_ALG, SIGN_ALG,
};
pub use transport::{
    discover_server, interpret_rpc, parse_body, CallOutcome, HttpTransport, Transport,
    TransportError,
};
