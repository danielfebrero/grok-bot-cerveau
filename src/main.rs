use std::io::{self, Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::Value;

use cerveau::{
    default_home, generate_agent_key, load_agent_key, parse_messages, queue_drop, queue_status,
    report_json, validate_endpoint, Client, ClientConfig, MessageOrigin, RunInput, TurnMessage,
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
        Cmd::Keygen(args) => {
            let home = home(args.agent.dir)?;
            let export = generate_agent_key(&home, &args.agent.agent, args.force)?;
            println!("{}", serde_json::to_string_pretty(&export)?);
        }
        Cmd::Pubkey(args) => {
            let home = home(args.dir)?;
            let key = load_agent_key(&home, &args.agent)?;
            println!("{}", serde_json::to_string_pretty(&key.public_export())?);
        }
        Cmd::Run(args) => {
            let home = home(args.agent.dir.clone())?;
            let mut config = ClientConfig::from_env(&args.agent.agent, home)?;
            if let Some(endpoint) = args.endpoint.as_deref() {
                config.endpoint = Some(validate_endpoint(endpoint)?);
            }
            let input = read_input(&args)?;
            let client = Client::new(config);
            let report = client.run(input)?;
            println!("{}", serde_json::to_string_pretty(&report_json(&report))?);
        }
        Cmd::Replay(args) => {
            let home = home(args.dir)?;
            let config = ClientConfig::from_env(&args.agent, home)?;
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
            let home = home(args.agent.dir)?;
            if let Some(run_id) = args.drop_run {
                let removed = queue_drop(&home, &args.agent.agent, &run_id)?;
                println!(
                    "{}",
                    serde_json::json!({"dropped": removed, "run_id": run_id})
                );
            } else {
                let status = queue_status(&home, &args.agent.agent)?;
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

fn home(flag: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = flag {
        return Ok(path);
    }
    Ok(default_home()?)
}

fn read_input(args: &RunArgs) -> Result<RunInput, Box<dyn std::error::Error>> {
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
        messages.extend(parse_messages(&value)?);
    }
    let mut trigger = None;
    match (&args.human_from, &args.human_text) {
        (None, None) => {}
        (Some(from), Some(text)) => {
            let message = TurnMessage {
                origin: MessageOrigin::Human { from: from.clone() },
                text: text.clone(),
                ref_id: None,
                at: None,
            };
            trigger = Some(message.clone());
            messages.push(message);
        }
        _ => {
            return Err("--human-from and --human-text are both required".into());
        }
    }
    if transcript.is_empty() && messages.is_empty() {
        return Err("provide --transcript, --messages, or --human-text".into());
    }
    Ok(RunInput {
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

#[derive(Parser)]
#[command(
    name = "cerveau",
    version,
    about = "Box-side client for the Cerveau MCP"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an ed25519 key for one agent and print only the public export.
    Keygen(KeygenArgs),
    /// Print the public key and key_id.
    Pubkey(AgentArgs),
    /// Seal this turn, drain older queued runs, then call cerveau.run.
    Run(RunArgs),
    /// Replay the encrypted local queue in seq order.
    Replay(AgentArgs),
    /// List queued run ids, or drop one by run_id. Never prints plaintext.
    Queue(QueueArgs),
}

#[derive(clap::Args)]
struct AgentArgs {
    #[arg(long, env = "CERVEAU_AGENT")]
    agent: String,
    #[arg(long, env = "CERVEAU_HOME")]
    dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct KeygenArgs {
    #[command(flatten)]
    agent: AgentArgs,
    /// Replace an existing key. Refused while a queue file is present.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args)]
struct RunArgs {
    #[command(flatten)]
    agent: AgentArgs,
    /// Verbatim transcript. Use "-" for stdin. Not attributed to anyone.
    #[arg(long)]
    transcript: Option<PathBuf>,
    /// JSON array of attributed messages.
    #[arg(long)]
    messages: Option<PathBuf>,
    /// Sender of text the human typed in this turn. "dani" is allowed only here.
    #[arg(long)]
    human_from: Option<String>,
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
    agent: AgentArgs,
    #[arg(long = "drop")]
    drop_run: Option<String>,
}
