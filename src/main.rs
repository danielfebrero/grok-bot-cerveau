use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::Value;

use cerveau::{
    add_principal, config_home, data_home, generate_agent_key, init_install, load_agent_key,
    parse_messages, pin_server, queue_drop, queue_status, registration_bundle, report_json,
    revoke_key, rotate_agent_key, validate_endpoint, Client, ClientConfig, InitRequest,
    MessageOrigin, PresentedServer, RunInput, TurnMessage,
};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("cerveau: {err}");
            2
        }
    };
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    std::process::exit(code);
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Init(args) => {
            let config_dir = config_dir(args.paths.config_dir)?;
            let data_dir = data_dir(args.paths.data_dir)?;
            let tenant_id = required(args.tenant, "tenant", "Tenant id")?;
            let principal_id = required(args.principal_id, "principal-id", "Principal id")?;
            let display_name =
                required(args.display_name, "display-name", "Principal display name")?;
            let agent_id = required(args.agent, "agent", "First agent id")?;
            let endpoint = optional(args.endpoint, "MCP endpoint URL (empty to set later)")?;
            let recipient_key_id = optional(
                args.recipient_key_id,
                "Server recipient key id (empty to pin later)",
            )?;
            let recipient_public = optional_key(
                args.recipient_public_key,
                "Server X25519 public key, base64 (empty to pin later)",
            )?;
            let signing_key_id =
                optional(args.signing_key_id, "Server signing key id (empty to skip)")?;
            let signing_public = optional_key(
                args.signing_public_key,
                "Server ed25519 signing public key, base64 (empty to skip)",
            )?;
            init_install(InitRequest {
                config_dir: config_dir.clone(),
                data_dir: data_dir.clone(),
                tenant_id: tenant_id.clone(),
                principal_id: principal_id.clone(),
                display_name,
                agent_id: agent_id.clone(),
                endpoint,
                recipient_key_id,
                recipient_public,
                signing_key_id,
                signing_public,
                tool_name: None,
            })?;
            let bundle = registration_bundle(
                &config_dir,
                &data_dir,
                &tenant_id,
                &agent_id,
                Some(&principal_id),
            )?;
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        Cmd::Principal(args) => {
            let config_dir = config_dir(args.paths.config_dir)?;
            let tenant_id = required(args.tenant, "tenant", "Tenant id")?;
            let principal_id = required(args.principal_id, "principal-id", "Principal id")?;
            let display_name =
                required(args.display_name, "display-name", "Principal display name")?;
            let principal = add_principal(&config_dir, &tenant_id, &principal_id, &display_name)?;
            println!("{}", serde_json::to_string_pretty(&principal)?);
        }
        Cmd::Keygen(args) => {
            let data = data_dir(args.scope.paths.data_dir)?;
            let export = generate_agent_key(&data, &args.scope.tenant, &args.scope.agent)?;
            println!("{}", serde_json::to_string_pretty(&export)?);
        }
        Cmd::Pubkey(args) => {
            let data = data_dir(args.scope.paths.data_dir)?;
            let key = load_agent_key(&data, &args.scope.tenant, &args.scope.agent)?;
            println!("{}", serde_json::to_string_pretty(&key.public_export())?);
        }
        Cmd::Register(args) => {
            let config = config_dir(args.scope.paths.config_dir.clone())?;
            let data = data_dir(args.scope.paths.data_dir.clone())?;
            let bundle = registration_bundle(
                &config,
                &data,
                &args.scope.tenant,
                &args.scope.agent,
                args.principal.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        Cmd::Rotate(args) => {
            let config = config_dir(args.scope.paths.config_dir.clone())?;
            let data = data_dir(args.scope.paths.data_dir.clone())?;
            rotate_agent_key(&data, &args.scope.tenant, &args.scope.agent)?;
            let bundle = registration_bundle(
                &config,
                &data,
                &args.scope.tenant,
                &args.scope.agent,
                args.principal.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        Cmd::Revoke(args) => {
            let data = data_dir(args.scope.paths.data_dir)?;
            revoke_key(&data, &args.scope.tenant, &args.scope.agent, &args.key_id)?;
            println!(
                "{}",
                serde_json::json!({"revoked": args.key_id, "tenant_id": args.scope.tenant})
            );
        }
        Cmd::Pin(args) => {
            let config = config_dir(args.paths.config_dir)?;
            let tenant = required(args.tenant, "tenant", "Tenant id")?;
            let recipient_key_id = required(
                args.recipient_key_id,
                "recipient-key-id",
                "Server recipient key id",
            )?;
            let recipient_public = require_key(
                args.recipient_public_key,
                "recipient-public-key",
                "Server X25519 public key, base64",
            )?;
            let signing_public = optional_key(
                args.signing_public_key,
                "Server ed25519 signing public key, base64 (empty to skip)",
            )?;
            let signing_key_id = match (&args.signing_key_id, signing_public.is_some()) {
                (Some(id), true) => Some(id.clone()),
                (None, false) => None,
                _ => {
                    return Err("signing key id and signing public key must be set together".into())
                }
            };
            let server = pin_server(
                &config,
                &tenant,
                &PresentedServer {
                    endpoint: args.endpoint,
                    recipient_key_id: Some(recipient_key_id),
                    recipient_public: Some(recipient_public),
                    signing_key_id,
                    signing_public,
                    trust_on_first_use: false,
                },
                args.replace,
            )?;
            println!("{}", serde_json::to_string_pretty(&server)?);
        }
        Cmd::Run(args) => {
            let config = open_client(&args.scope, args.principal.clone(), args.endpoint.clone())?;
            let input = read_input(&args, &config.principal_id)?;
            let client = Client::new(config);
            let report = client.run(input)?;
            println!("{}", serde_json::to_string_pretty(&report_json(&report))?);
        }
        Cmd::Replay(args) => {
            let config = open_client(&args.scope, args.principal.clone(), None)?;
            let client = Client::new(config);
            let report = client.replay()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "flushed": report.flushed,
                    "remaining": report.remaining,
                    "stopped": report.stopped.as_ref().map(|r| r.as_str()),
                }))?
            );
        }
        Cmd::Queue(args) => {
            let data = data_dir(args.scope.paths.data_dir)?;
            if let Some(run_id) = args.drop_run {
                let removed = queue_drop(&data, &args.scope.tenant, &args.scope.agent, &run_id)?;
                println!(
                    "{}",
                    serde_json::json!({"dropped": removed, "run_id": run_id})
                );
            } else {
                let status = queue_status(&data, &args.scope.tenant, &args.scope.agent)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pending": status.pending,
                        "seqs": status.seqs,
                        "run_ids": status.run_ids,
                    }))?
                );
            }
        }
    }
    Ok(())
}

fn open_client(
    scope: &Scope,
    principal: Option<String>,
    endpoint: Option<String>,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let config_dir = config_dir(scope.paths.config_dir.clone())?;
    let data_dir = data_dir(scope.paths.data_dir.clone())?;
    let mut config = ClientConfig::from_env(
        scope.tenant.clone(),
        scope.agent.clone(),
        principal,
        config_dir,
        data_dir,
    )?;
    if let Some(endpoint) = endpoint.as_deref() {
        config.endpoint = Some(validate_endpoint(endpoint)?);
    }
    Ok(config)
}

fn config_dir(flag: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = flag {
        return Ok(path);
    }
    Ok(config_home()?)
}

fn data_dir(flag: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = flag {
        return Ok(path);
    }
    Ok(data_home()?)
}

fn read_input(args: &RunArgs, principal_id: &str) -> Result<RunInput, Box<dyn std::error::Error>> {
    let transcript = match &args.transcript {
        Some(path) if path.as_os_str() == "-" => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
        Some(path) => std::fs::read_to_string(path)?,
        None => String::new(),
    };
    let mut messages = Vec::new();
    if let Some(path) = &args.messages {
        let raw = std::fs::read_to_string(path)?;
        let value: Value = serde_json::from_str(&raw)?;
        messages.extend(parse_messages(&value, principal_id)?);
    }
    let mut trigger = None;
    if let Some(text) = &args.human_text {
        let message = TurnMessage {
            origin: MessageOrigin::Human { claimed_from: None },
            text: text.clone(),
            ref_id: None,
            at: None,
        };
        trigger = Some(message.clone());
        messages.push(message);
    }
    if transcript.is_empty() && messages.is_empty() {
        return Err("provide --transcript, --messages, or --human-text".into());
    }
    Ok(RunInput {
        tenant_id: args.scope.tenant.clone(),
        principal_id: args
            .principal
            .clone()
            .unwrap_or_else(|| principal_id.to_string()),
        transcript,
        prev_envelope_id: args.prev_envelope.clone(),
        trigger,
        messages,
        tool_results: Vec::new(),
        decisions: Vec::new(),
        redact_emails: args.redact_emails,
        redact_phones: args.redact_phones,
    })
}

fn required(
    value: Option<String>,
    flag: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(value) = value.filter(|s| !s.trim().is_empty()) {
        return Ok(value.trim().to_string());
    }
    prompt(flag, label)
}

fn optional(
    value: Option<String>,
    label: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(value) = value {
        let value = value.trim().to_string();
        return Ok(if value.is_empty() { None } else { Some(value) });
    }
    if !io::stdin().is_terminal() {
        return Ok(None);
    }
    let value = prompt_raw(label)?;
    Ok(if value.is_empty() { None } else { Some(value) })
}

fn optional_key(
    value: Option<String>,
    label: &str,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    let Some(raw) = optional(value, label)? else {
        return Ok(None);
    };
    Ok(Some(decode_key(&raw)?))
}

fn require_key(
    value: Option<String>,
    flag: &str,
    label: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = required(value, flag, label)?;
    decode_key(&raw)
}

fn decode_key(raw: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw.trim()))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    Ok(bytes)
}

fn prompt(flag: &str, label: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !io::stdin().is_terminal() {
        return Err(format!("missing --{flag}").into());
    }
    let value = prompt_raw(label)?;
    if value.is_empty() {
        return Err(format!("missing --{flag}").into());
    }
    Ok(value)
}

fn prompt_raw(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{label}: ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[derive(Parser)]
#[command(
    name = "cerveau",
    version,
    about = "Box-side client for a Cerveau-compatible MCP"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a tenant, its first principal, and its first agent key.
    Init(InitArgs),
    /// Add another principal to an install.
    Principal(PrincipalArgs),
    /// Generate an ed25519 key for another agent of an existing tenant.
    Keygen(ScopeArgs),
    /// Print the active public key and key_id.
    Pubkey(ScopeArgs),
    /// Print the registration bundle for the backend operator to approve.
    Register(RegisterArgs),
    /// Rotate the active agent key. seq continues; the previous key is retired.
    Rotate(RegisterArgs),
    /// Mark a retired key revoked. Rotate the active key instead of revoking it.
    Revoke(RevokeArgs),
    /// Pin the server X25519 key. A different key is refused unless --replace is set.
    Pin(PinArgs),
    /// Seal this turn, drain older queued runs, then call the configured backend.
    Run(RunArgs),
    /// Replay the encrypted local queue in seq order.
    Replay(ReplayArgs),
    /// List queued run ids, or drop one by run_id. Never prints plaintext.
    Queue(QueueArgs),
}

#[derive(clap::Args)]
struct Paths {
    #[arg(long, env = "CERVEAU_CONFIG_HOME")]
    config_dir: Option<PathBuf>,
    #[arg(long, env = "CERVEAU_DATA_HOME")]
    data_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct Scope {
    #[arg(long, env = "CERVEAU_TENANT")]
    tenant: String,
    #[arg(long, env = "CERVEAU_AGENT")]
    agent: String,
    #[command(flatten)]
    paths: Paths,
}

#[derive(clap::Args)]
struct ScopeArgs {
    #[command(flatten)]
    scope: Scope,
}

#[derive(clap::Args)]
struct InitArgs {
    #[arg(long, env = "CERVEAU_TENANT")]
    tenant: Option<String>,
    #[arg(long, env = "CERVEAU_PRINCIPAL")]
    principal_id: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long, env = "CERVEAU_AGENT")]
    agent: Option<String>,
    #[arg(long, env = "CERVEAU_MCP_URL")]
    endpoint: Option<String>,
    #[arg(long, env = "CERVEAU_RECIPIENT_KEY_ID")]
    recipient_key_id: Option<String>,
    #[arg(long, env = "CERVEAU_RECIPIENT_PUBLIC_KEY")]
    recipient_public_key: Option<String>,
    #[arg(long, env = "CERVEAU_SIGNING_KEY_ID")]
    signing_key_id: Option<String>,
    #[arg(long, env = "CERVEAU_SIGNING_PUBLIC_KEY")]
    signing_public_key: Option<String>,
    #[command(flatten)]
    paths: Paths,
}

#[derive(clap::Args)]
struct PrincipalArgs {
    #[arg(long, env = "CERVEAU_TENANT")]
    tenant: Option<String>,
    #[arg(long)]
    principal_id: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[command(flatten)]
    paths: Paths,
}

#[derive(clap::Args)]
struct RegisterArgs {
    #[command(flatten)]
    scope: Scope,
    #[arg(long, env = "CERVEAU_PRINCIPAL")]
    principal: Option<String>,
}

#[derive(clap::Args)]
struct RevokeArgs {
    #[command(flatten)]
    scope: Scope,
    #[arg(long)]
    key_id: String,
}

#[derive(clap::Args)]
struct PinArgs {
    #[arg(long, env = "CERVEAU_TENANT")]
    tenant: Option<String>,
    #[arg(long, env = "CERVEAU_MCP_URL")]
    endpoint: Option<String>,
    #[arg(long, env = "CERVEAU_RECIPIENT_KEY_ID")]
    recipient_key_id: Option<String>,
    #[arg(long, env = "CERVEAU_RECIPIENT_PUBLIC_KEY")]
    recipient_public_key: Option<String>,
    #[arg(long, env = "CERVEAU_SIGNING_KEY_ID")]
    signing_key_id: Option<String>,
    #[arg(long, env = "CERVEAU_SIGNING_PUBLIC_KEY")]
    signing_public_key: Option<String>,
    /// Replace a pin that already holds a different key.
    #[arg(long)]
    replace: bool,
    #[command(flatten)]
    paths: Paths,
}

#[derive(clap::Args)]
struct ReplayArgs {
    #[command(flatten)]
    scope: Scope,
    #[arg(long, env = "CERVEAU_PRINCIPAL")]
    principal: Option<String>,
}

#[derive(clap::Args)]
struct RunArgs {
    #[command(flatten)]
    scope: Scope,
    #[arg(long, env = "CERVEAU_PRINCIPAL")]
    principal: Option<String>,
    /// Verbatim transcript. Use "-" for stdin. Not attributed to anyone.
    #[arg(long)]
    transcript: Option<PathBuf>,
    /// JSON array of attributed messages.
    #[arg(long)]
    messages: Option<PathBuf>,
    /// Text the selected principal typed in this turn.
    #[arg(long)]
    human_text: Option<String>,
    #[arg(long)]
    prev_envelope: Option<String>,
    #[arg(long, env = "CERVEAU_MCP_URL")]
    endpoint: Option<String>,
    #[arg(long)]
    redact_emails: bool,
    #[arg(long)]
    redact_phones: bool,
}

#[derive(clap::Args)]
struct QueueArgs {
    #[command(flatten)]
    scope: Scope,
    #[arg(long = "drop")]
    drop_run: Option<String>,
}
