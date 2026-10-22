//! Box-side client for the Cerveau MCP.
//!
//! Before a turn, an agent calls [`Client::run`]. The client redacts secret
//! spans, seals the filtered transcript to Cerveau, and signs the ciphertext.
//! The returned [`TurnContext`] is read-only context: it never overrides the
//! agent's base rules or the approvals required before a side effect.
//!
//! Pending runs are replayed in `seq` order before any newer direct send.
//! A run N+1 is never sent with `replay: false` while run N is still queued.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("cerveau stores private keys with Unix mode 0600 and only builds on Unix");

mod b64;
mod body;
mod canon;
mod client;
mod crypto;
mod envelope;
mod id;
mod key;
mod queue;
mod redact;
mod seal;
mod transport;
mod util;

pub use body::{
    parse_message, parse_messages, prepare_body, AttributionError, Decision, MessageOrigin,
    RunBody, RunInput, ToolResult, TranscriptEntry, TurnMessage, BODY_SCHEMA, OPERATOR_FROM,
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
pub use id::{is_key_id, is_run_id, is_token, AGENT_ID_MAX, KEY_ID_MAX, RUN_ID_MAX};
pub use key::{
    agent_dir, default_home, generate_agent_key, load_agent_key, AgentKey, KeyError, PublicExport,
    KEY_SCHEMA, PUB_SCHEMA,
};
pub use redact::{redact_text, RedactOptions, Redaction};
pub use seal::{
    associated_data, hkdf_info, hkdf_salt, open_run, seal_run, signature_preimage, EncBlock,
    RunMessage, SealError, SealRandomness, SealRequest, SigBlock, RUN_SCHEMA, SEAL_ALG, SIGN_ALG,
};
pub use transport::{
    interpret_rpc, parse_body, CallOutcome, HttpTransport, Transport, TransportError,
};
