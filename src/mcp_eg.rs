//! Boucle MCP Streamable HTTP du claim EG.
//!
//! Le jeton ne choisit pas le compte. Le serveur le fait, à partir du bearer
//! ou, si le fichier de signature est là, à partir de la clé publique.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::client::validate_endpoint;
use crate::transport::parse_body;

pub const PROTOCOL: &str = "2025-06-18";
pub const DEFAULT_CONVERSATION: &str = "default";
pub const CALL_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Error)]
pub enum EgError {
    #[error("endpoint: {0}")]
    Endpoint(String),
    #[error("mcp token file: {0}")]
    Token(String),
    #[error("turn: {0}")]
    Turn(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("mcp: {0}")]
    Rpc(String),
}

/// Bearer lu dans un fichier 0600. Effacé à la destruction.
pub struct TokenFile {
    value: String,
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl TokenFile {
    pub fn load(path: &Path) -> Result<Self, EgError> {
        let meta =
            std::fs::symlink_metadata(path).map_err(|_| EgError::Token("unreadable".into()))?;
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
        let raw = std::fs::read(path).map_err(|_| EgError::Token("unreadable".into()))?;
        let text = String::from_utf8(raw).map_err(|_| EgError::Token("not utf-8".into()))?;
        let value = text.trim().to_string();
        if !(16..=512).contains(&value.len())
            || value
                .chars()
                .any(|c| c.is_whitespace() || !c.is_ascii_graphic())
        {
            return Err(EgError::Token("rejected".into()));
        }
        Ok(Self { value })
    }

    fn authorization(&self) -> String {
        format!("Bearer {}", self.value)
    }
}

pub fn default_token_path(config_dir: &Path) -> PathBuf {
    config_dir.join("mcp-token")
}

/// `true` quand ce tour doit parler au MCP EG plutôt qu'au protocole scellé.
pub fn wants_mcp(
    endpoint: Option<&str>,
    token_path: &Path,
    signing_path: &Path,
    forced: bool,
) -> bool {
    if forced || token_path.is_file() || signing_path.is_file() {
        return true;
    }
    endpoint.is_some_and(|url| {
        let path = path_of(url);
        is_mcp_path(&path) || is_retired_path(&path)
    })
}

pub fn mcp_url(url: &str) -> Result<String, EgError> {
    let url = validate_endpoint(url).map_err(|_| EgError::Endpoint("invalid".into()))?;
    let rewritten = rewrite_retired(&url);
    if !is_mcp_path(&path_of(&rewritten)) {
        return Err(EgError::Endpoint("path must be /mcp".into()));
    }
    Ok(rewritten)
}

pub fn stable_ref(conversation: &str, goal: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(conversation.as_bytes());
    hasher.update([0]);
    hasher.update(goal.as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

pub struct TurnRequest<'a> {
    pub endpoint: &'a str,
    /// Ignoré quand `signing` est présent : les deux ensemble signent seulement.
    pub token: Option<&'a TokenFile>,
    pub signing: Option<&'a crate::mcp_sig::SigningFile>,
    pub goal: &'a str,
    pub ref_id: &'a str,
    pub conversation_id: &'a str,
    pub reply: Option<&'a str>,
    pub timeout: Duration,
}

/// `channel_thread` `context`, puis `transcript_append` si une réponse est donnée.
pub fn context_turn(req: &TurnRequest<'_>) -> Result<Value, EgError> {
    check_piece("goal", req.goal, 32_000)?;
    check_piece("ref_id", req.ref_id, 200)?;
    check_piece("conversation_id", req.conversation_id, 200)?;
    if let Some(reply) = req.reply {
        check_piece("body", reply, 32_000)?;
    }
    let url = mcp_url(req.endpoint)?;
    let mut session = Session::open(&url, req.signing, req.token, req.timeout)?;
    session.initialize()?;
    session.notify_initialized()?;
    session.require_channel_thread()?;
    let context =
        session.call_thread("context", "goal", req.goal, req.ref_id, req.conversation_id)?;
    let persisted = if let Some(reply) = req.reply {
        Some(session.call_thread(
            "transcript_append",
            "body",
            reply,
            req.ref_id,
            req.conversation_id,
        )?)
    } else {
        None
    };
    let thread_id = context
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(json!({
        "outcome": "context",
        "thread_id": thread_id,
        "ref_id": req.ref_id,
        "conversation_id": req.conversation_id,
        "context": context,
        "persisted": persisted,
    }))
}

pub fn append_turn(
    endpoint: &str,
    token: Option<&TokenFile>,
    signing: Option<&crate::mcp_sig::SigningFile>,
    conversation_id: &str,
    ref_id: &str,
    body: &str,
    timeout: Duration,
) -> Result<Value, EgError> {
    check_piece("body", body, 32_000)?;
    check_piece("ref_id", ref_id, 200)?;
    check_piece("conversation_id", conversation_id, 200)?;
    let url = mcp_url(endpoint)?;
    let mut session = Session::open(&url, signing, token, timeout)?;
    session.initialize()?;
    session.notify_initialized()?;
    let persisted =
        session.call_thread("transcript_append", "body", body, ref_id, conversation_id)?;
    Ok(json!({
        "outcome": "appended",
        "ref_id": ref_id,
        "conversation_id": conversation_id,
        "persisted": persisted,
    }))
}

enum CallAuth<'a> {
    Bearer(String),
    Sign(&'a crate::mcp_sig::SigningFile),
}

struct Session<'a> {
    agent: ureq::Agent,
    endpoint: String,
    auth: CallAuth<'a>,
    session_id: Option<String>,
    protocol: String,
    next_id: i64,
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let CallAuth::Bearer(value) = &mut self.auth {
            value.zeroize();
        }
    }
}

impl<'a> Session<'a> {
    fn open(
        endpoint: &str,
        signing: Option<&'a crate::mcp_sig::SigningFile>,
        token: Option<&TokenFile>,
        timeout: Duration,
    ) -> Result<Self, EgError> {
        if timeout.is_zero() {
            return Err(EgError::Transport("timeout".into()));
        }
        let auth = if let Some(signing) = signing {
            CallAuth::Sign(signing)
        } else if let Some(token) = token {
            CallAuth::Bearer(token.authorization())
        } else {
            return Err(EgError::Token("missing".into()));
        };
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .max_idle_connections(0)
            .build();
        Ok(Self {
            agent,
            endpoint: endpoint.to_string(),
            auth,
            session_id: None,
            protocol: PROTOCOL.to_string(),
            next_id: 1,
        })
    }

    fn initialize(&mut self) -> Result<(), EgError> {
        let id = self.alloc_id();
        let (session, value) = self.post(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "cerveau",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            }),
            false,
        )?;
        self.session_id = session;
        if let Some(version) = value
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
        {
            if matches!(version, "2024-11-05" | "2025-03-26" | "2025-06-18") {
                self.protocol = version.to_string();
            }
        }
        Ok(())
    }

    fn notify_initialized(&mut self) -> Result<(), EgError> {
        let _ = self.post(
            &json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            true,
        )?;
        Ok(())
    }

    fn require_channel_thread(&mut self) -> Result<(), EgError> {
        let id = self.alloc_id();
        let (_, value) = self.post(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/list",
                "params": {}
            }),
            false,
        )?;
        let tools = value
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .ok_or_else(|| EgError::Rpc("tools/list".into()))?;
        let present = tools
            .iter()
            .any(|tool| tool.get("name").and_then(Value::as_str) == Some("channel_thread"));
        if !present {
            return Err(EgError::Rpc("channel_thread absent".into()));
        }
        Ok(())
    }

    fn call_thread(
        &mut self,
        action: &str,
        field: &str,
        text: &str,
        ref_id: &str,
        conversation_id: &str,
    ) -> Result<Value, EgError> {
        let id = self.alloc_id();
        let (_, value) = self.post(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "channel_thread",
                    "arguments": {
                        "action": action,
                        field: text,
                        "ref_id": ref_id,
                        "conversation_id": conversation_id
                    }
                }
            }),
            false,
        )?;
        tool_payload(&value)
    }

    fn alloc_id(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn post(
        &mut self,
        payload: &Value,
        allow_empty: bool,
    ) -> Result<(Option<String>, Value), EgError> {
        let body = serde_json::to_string(payload).map_err(|_| EgError::Rpc("encode".into()))?;
        let mut request = self
            .agent
            .post(&self.endpoint)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("MCP-Protocol-Version", &self.protocol)
            .set(
                "User-Agent",
                concat!("cerveau-client/", env!("CARGO_PKG_VERSION")),
            )
            .set("Connection", "close");
        match &self.auth {
            CallAuth::Bearer(authorization) => {
                request = request.set("Authorization", authorization);
            }
            CallAuth::Sign(key) => {
                let authority = crate::mcp_sig::authority_of(&self.endpoint)?;
                let path = path_of(&self.endpoint);
                let signed = key.sign(&crate::mcp_sig::SignRequest {
                    method: "POST",
                    authority: &authority,
                    path: &path,
                    content_type: "application/json",
                    body: body.as_bytes(),
                    session_id: self.session_id.as_deref(),
                    created: crate::mcp_sig::unix_now(),
                })?;
                request = request
                    .set("Content-Digest", &signed.content_digest)
                    .set("Signature-Input", &signed.signature_input)
                    .set("Signature", &signed.signature);
            }
        }
        if let Some(session) = &self.session_id {
            request = request.set("Mcp-Session-Id", session);
        }
        let response = request.send_string(&body).map_err(|err| match err {
            ureq::Error::Status(code, _) => EgError::Transport(format!("http {code}")),
            ureq::Error::Transport(err) => EgError::Transport(map_transport(&err)),
        })?;
        let session = response
            .header("mcp-session-id")
            .map(str::to_owned)
            .or_else(|| self.session_id.clone());
        let content_type = response.content_type().to_string();
        let mut buf = String::new();
        response
            .into_reader()
            .take(2 * 1024 * 1024 + 1)
            .read_to_string(&mut buf)
            .map_err(|_| EgError::Rpc("body".into()))?;
        if buf.len() > 2 * 1024 * 1024 {
            return Err(EgError::Rpc("body".into()));
        }
        if buf.trim().is_empty() {
            if allow_empty {
                return Ok((session, Value::Null));
            }
            return Err(EgError::Rpc("empty".into()));
        }
        let value = parse_body(&content_type, &buf).map_err(|_| EgError::Rpc("body".into()))?;
        if let Some(error) = value.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error");
            return Err(EgError::Rpc(clip(message)));
        }
        Ok((session, value))
    }
}

fn tool_payload(value: &Value) -> Result<Value, EgError> {
    let result = value
        .get("result")
        .ok_or_else(|| EgError::Rpc("result".into()))?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(EgError::Rpc(clip(&result.to_string())));
    }
    if let Some(structured) = result.get("structuredContent").filter(|v| v.is_object()) {
        return Ok(structured.clone());
    }
    if let Some(items) = result.get("content").and_then(Value::as_array) {
        for item in items {
            let Some(text) = item.get("text").and_then(Value::as_str) else {
                continue;
            };
            if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                if parsed.is_object() {
                    return Ok(parsed);
                }
            }
        }
    }
    if result.is_object() && result.get("content").is_none() {
        return Ok(result.clone());
    }
    Err(EgError::Rpc("payload".into()))
}

fn check_piece(name: &str, value: &str, max: usize) -> Result<(), EgError> {
    if value.trim().is_empty() || value.chars().count() > max || value.contains('\0') {
        return Err(EgError::Turn(name.into()));
    }
    Ok(())
}

fn clip(text: &str) -> String {
    let mut out: String = text.chars().take(300).collect();
    if let Some(start) = out.find("Bearer ") {
        out.replace_range(start.., "Bearer [redacted]");
    }
    out
}

fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let path = rest.split(['?', '#']).next().unwrap_or(rest);
    let path = path.split_once('/').map(|(_, p)| p).unwrap_or("");
    if path.is_empty() {
        "/".into()
    } else {
        format!("/{path}")
    }
}

fn is_mcp_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == "/mcp"
}

fn is_retired_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == "/cerveau"
}

fn rewrite_retired(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (host, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/".into()),
    };
    let path_only = path.split(['?', '#']).next().unwrap_or(path.as_str());
    if is_retired_path(path_only) {
        format!("{scheme}://{host}/mcp")
    } else {
        let trimmed = path_only.trim_end_matches('/');
        if trimmed.is_empty() {
            format!("{scheme}://{host}/")
        } else {
            format!("{scheme}://{host}{trimmed}")
        }
    }
}

fn map_transport(err: &ureq::Transport) -> String {
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        "timeout".into()
    } else {
        "unreachable".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn retired_cerveau_url_becomes_mcp() {
        assert_eq!(
            mcp_url("https://grok.example/cerveau").unwrap(),
            "https://grok.example/mcp"
        );
        assert!(mcp_url("https://grok.example/other").is_err());
    }

    #[test]
    fn ref_id_is_stable_and_changes_with_the_goal() {
        assert_eq!(
            stable_ref("default", "bonjour"),
            stable_ref("default", "bonjour")
        );
        assert_ne!(
            stable_ref("default", "bonjour"),
            stable_ref("default", "autre")
        );
        assert_ne!(
            stable_ref("default", "bonjour"),
            stable_ref("autre", "bonjour")
        );
    }

    #[test]
    fn token_file_must_be_mode_0600_and_not_a_symlink() {
        let root = std::env::temp_dir().join(format!("cerveau-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("mcp-token");
        std::fs::write(&path, "abcdefghijklmnop").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(TokenFile::load(&path).is_err());
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(TokenFile::load(&path).is_ok());
        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(TokenFile::load(&link).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn context_roundtrip_sends_no_account_field_and_hides_the_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = "test-token-value-0600";
        let server = thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = stream.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let text = String::from_utf8_lossy(&buf);
                        let header_len = text.find("\r\n\r\n").unwrap() + 4;
                        let len = text
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= header_len + len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                seen.push(text.clone());
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
                let method = body
                    .split("\"method\":\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("");
                let (status, extra, payload) = match method {
                    "initialize" => (
                        "200 OK",
                        "Content-Type: application/json\r\nmcp-session-id: sess-1\r\n",
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{}}}",
                    ),
                    "notifications/initialized" => ("202 Accepted", "", ""),
                    "tools/list" => (
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"channel_thread\"}]}}",
                    ),
                    "tools/call" => (
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"structuredContent\":{\"thread_id\":\"tid\",\"goal\":\"bonjour\"}}}",
                    ),
                    _ => ("500 ERR", "", ""),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });

        let root = std::env::temp_dir().join(format!("cerveau-mcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("mcp-token");
        std::fs::write(&path, secret).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
        let token = TokenFile::load(&path).unwrap();
        let report = context_turn(&TurnRequest {
            endpoint: &format!("http://127.0.0.1:{port}/mcp"),
            token: Some(&token),
            signing: None,
            goal: "bonjour",
            ref_id: "ref-1",
            conversation_id: "default",
            reply: None,
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        assert_eq!(report["context"]["thread_id"], "tid");
        assert_eq!(report["outcome"], "context");
        let seen = server.join().unwrap();
        let call = seen.iter().find(|s| s.contains("tools/call")).unwrap();
        assert!(call.contains("Bearer test-token-value-0600"));
        assert!(call.contains("Mcp-Session-Id: sess-1") || call.contains("mcp-session-id: sess-1"));
        assert!(call.contains("\"action\":\"context\""));
        assert!(!call.contains("actor_id"));
        assert!(!call.contains("partner"));
        assert!(!format!("{report}").contains(secret));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn http_failure_does_not_include_the_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        let root = std::env::temp_dir().join(format!("cerveau-mcp-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("mcp-token");
        let secret = "denied-token-value-0600";
        std::fs::write(&path, secret).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
        let token = TokenFile::load(&path).unwrap();
        let err = context_turn(&TurnRequest {
            endpoint: &format!("http://127.0.0.1:{port}/mcp"),
            token: Some(&token),
            signing: None,
            goal: "bonjour",
            ref_id: "ref-1",
            conversation_id: "default",
            reply: None,
            timeout: Duration::from_secs(2),
        })
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("401"), "{text}");
        assert!(!text.contains(secret), "{text}");
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn signing_sends_no_authorization() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = stream.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let text = String::from_utf8_lossy(&buf);
                        let header_len = text.find("\r\n\r\n").unwrap() + 4;
                        let len = text
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= header_len + len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                seen.push(text.clone());
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
                let method = body
                    .split("\"method\":\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("");
                let (status, extra, payload) = match method {
                    "initialize" => (
                        "200 OK",
                        "Content-Type: application/json\r\nmcp-session-id: sess-1\r\n",
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{}}}",
                    ),
                    "notifications/initialized" => ("202 Accepted", "", ""),
                    "tools/list" => (
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"channel_thread\"}]}}",
                    ),
                    "tools/call" => (
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"structuredContent\":{\"thread_id\":\"tid\"}}}",
                    ),
                    _ => ("500 ERR", "", ""),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });
        let root = std::env::temp_dir().join(format!("cerveau-mcp-sig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let public = crate::mcp_sig::generate(&root, "box-test").unwrap();
        let key = crate::mcp_sig::SigningFile::load(&crate::mcp_sig::default_signing_path(&root))
            .unwrap();
        let report = context_turn(&TurnRequest {
            endpoint: &format!("http://127.0.0.1:{port}/mcp"),
            token: None,
            signing: Some(&key),
            goal: "bonjour",
            ref_id: "ref-1",
            conversation_id: "default",
            reply: None,
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        assert_eq!(report["outcome"], "context");
        let seen = server.join().unwrap();
        let init = seen.iter().find(|s| s.contains("initialize")).unwrap();
        let call = seen.iter().find(|s| s.contains("tools/call")).unwrap();
        for req in [init, call] {
            let lower = req.to_ascii_lowercase();
            assert!(!lower.contains("authorization"), "{req}");
            assert!(lower.contains("content-digest:"));
            assert!(lower.contains("signature-input:"));
            assert!(lower.contains("signature:"));
            assert!(req.contains("keyid=\"box-test\""));
            assert!(req.contains("alg=\"ed25519\""));
            assert!(!req.contains(&public));
        }
        assert!(call.contains("mcp-session-id"));
        assert!(call.contains("\"mcp-session-id\""));
        let _ = std::fs::remove_dir_all(&root);
    }
}
