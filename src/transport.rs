use std::io::Read;
use std::time::Duration;

use serde_json::Value;

use crate::envelope::TURN_SCHEMA;
use crate::seal::RunMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOutcome {
    pub envelope: Option<Value>,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Unreachable,
    EndpointUnset,
    Http(u16),
    Rpc,
    Protocol,
}

pub trait Transport: Send + Sync {
    fn call(&self, message: &RunMessage, timeout: Duration) -> Result<CallOutcome, TransportError>;
}

#[derive(Debug, Clone)]
pub struct HttpTransport {
    endpoint: Option<String>,
    tool_name: String,
    authorization: Option<String>,
    session_id: Option<String>,
}

/// Lit la clé publique du serveur dans la réponse `initialize`.
///
/// Absent : le serveur n'a pas encore publié de clé. L'appelant n'épingle rien.
pub fn discover_server(url: &str) -> Result<crate::install::PresentedServer, TransportError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .timeout_connect(Duration::from_secs(2))
        .timeout_read(Duration::from_secs(2))
        .build();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "cerveau", "version": env!("CARGO_PKG_VERSION")}
        }
    });
    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set("Connection", "close")
        .send_string(&payload.to_string())
        .map_err(|err| match err {
            ureq::Error::Status(code, _) => TransportError::Http(code),
            ureq::Error::Transport(err) => map_transport(&err),
        })?;
    let mut buf = String::new();
    response
        .into_reader()
        .take(64 * 1024 + 1)
        .read_to_string(&mut buf)
        .map_err(|_| TransportError::Protocol)?;
    if buf.len() > 64 * 1024 {
        return Err(TransportError::Protocol);
    }
    let value: Value = serde_json::from_str(&buf).map_err(|_| TransportError::Protocol)?;
    let info = value
        .pointer("/result/cerveau")
        .ok_or(TransportError::Protocol)?;
    let recipient_key_id = info
        .get("recipient_key_id")
        .and_then(Value::as_str)
        .ok_or(TransportError::Protocol)?
        .to_string();
    let recipient_raw = info
        .get("recipient_public_key")
        .and_then(Value::as_str)
        .ok_or(TransportError::Protocol)?;
    let recipient_public =
        crate::b64::decode_array(recipient_raw).map_err(|_| TransportError::Protocol)?;
    let signing = match (
        info.get("signing_key_id").and_then(Value::as_str),
        info.get("signing_public_key").and_then(Value::as_str),
    ) {
        (Some(id), Some(raw)) => Some((
            id.to_string(),
            crate::b64::decode_array(raw).map_err(|_| TransportError::Protocol)?,
        )),
        (None, None) => None,
        _ => return Err(TransportError::Protocol),
    };
    Ok(crate::install::PresentedServer {
        endpoint: Some(url.to_string()),
        recipient_key_id: Some(recipient_key_id),
        recipient_public: Some(recipient_public),
        signing_key_id: signing.as_ref().map(|(id, _)| id.clone()),
        signing_public: signing.map(|(_, key)| key),
        trust_on_first_use: true,
    })
}

impl HttpTransport {
    pub fn new(
        endpoint: Option<String>,
        tool_name: impl Into<String>,
        authorization: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            tool_name: tool_name.into(),
            authorization,
            session_id,
        }
    }
}

impl Transport for HttpTransport {
    fn call(&self, message: &RunMessage, timeout: Duration) -> Result<CallOutcome, TransportError> {
        let Some(url) = self.endpoint.as_deref() else {
            return Err(TransportError::EndpointUnset);
        };
        if timeout.is_zero() {
            return Err(TransportError::Timeout);
        }
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": message.run_id,
            "method": "tools/call",
            "params": {
                "name": self.tool_name,
                "arguments": message,
            }
        });
        let body = serde_json::to_string(&payload).map_err(|_| TransportError::Protocol)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .build();
        let mut request = agent
            .post(url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set(
                "User-Agent",
                concat!("cerveau-client/", env!("CARGO_PKG_VERSION")),
            )
            .set("Connection", "close");
        if let Some(auth) = &self.authorization {
            request = request.set("Authorization", auth);
        }
        if let Some(session) = &self.session_id {
            request = request.set("Mcp-Session-Id", session);
        }
        match request.send_string(&body) {
            Ok(response) => read_response(response, &message.run_id),
            Err(ureq::Error::Status(409, _response)) => Ok(CallOutcome {
                envelope: None,
                duplicate: true,
            }),
            Err(ureq::Error::Status(code, _response)) => Err(TransportError::Http(code)),
            Err(ureq::Error::Transport(err)) => Err(map_transport(&err)),
        }
    }
}

fn read_response(
    response: ureq::Response,
    expected_id: &str,
) -> Result<CallOutcome, TransportError> {
    let content_type = response.content_type().to_string();
    let mut buf = String::new();
    response
        .into_reader()
        .take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut buf)
        .map_err(|_| TransportError::Protocol)?;
    if buf.len() > 2 * 1024 * 1024 {
        return Err(TransportError::Protocol);
    }
    let value = parse_body(&content_type, &buf)?;
    if let Some(id) = value.get("id").and_then(Value::as_str) {
        if id != expected_id {
            return Err(TransportError::Protocol);
        }
    }
    interpret_rpc(&value)
}

fn map_transport(err: &ureq::Transport) -> TransportError {
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        TransportError::Timeout
    } else {
        TransportError::Unreachable
    }
}

pub fn parse_body(content_type: &str, body: &str) -> Result<Value, TransportError> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(TransportError::Protocol);
    }
    if content_type.contains("text/event-stream") || trimmed.starts_with("data:") {
        let mut last = None;
        for line in trimmed.lines() {
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            last = Some(serde_json::from_str(data).map_err(|_| TransportError::Protocol)?);
        }
        return last.ok_or(TransportError::Protocol);
    }
    serde_json::from_str(trimmed).map_err(|_| TransportError::Protocol)
}

pub fn interpret_rpc(value: &Value) -> Result<CallOutcome, TransportError> {
    if let Some(error) = value.get("error") {
        let message = error.get("message").and_then(Value::as_str).unwrap_or("");
        if is_duplicate_text(message) {
            return Ok(CallOutcome {
                envelope: None,
                duplicate: true,
            });
        }
        return Err(TransportError::Rpc);
    }
    let result = value.get("result").ok_or(TransportError::Protocol)?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        if is_duplicate_text(&result.to_string()) {
            return Ok(CallOutcome {
                envelope: None,
                duplicate: true,
            });
        }
        return Err(TransportError::Rpc);
    }
    if let Some(envelope) = envelope_in(result) {
        return Ok(CallOutcome {
            envelope: Some(envelope),
            duplicate: false,
        });
    }
    if is_duplicate_value(result) {
        return Ok(CallOutcome {
            envelope: None,
            duplicate: true,
        });
    }
    Ok(CallOutcome {
        envelope: None,
        duplicate: false,
    })
}

fn envelope_in(result: &Value) -> Option<Value> {
    if is_turn(result) {
        return Some(result.clone());
    }
    for key in ["structuredContent", "envelope"] {
        if let Some(child) = result.get(key).filter(|v| is_turn(v)) {
            return Some(child.clone());
        }
    }
    let items = result.get("content").and_then(Value::as_array)?;
    for item in items {
        let Some(text) = item.get("text").and_then(Value::as_str) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if is_turn(&parsed) {
            return Some(parsed);
        }
    }
    None
}

fn is_turn(value: &Value) -> bool {
    value.get("schema").and_then(Value::as_str) == Some(TURN_SCHEMA)
}

fn is_duplicate_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("duplicate") || lower.contains("already")
}

fn is_duplicate_value(value: &Value) -> bool {
    value.get("duplicate").and_then(Value::as_bool) == Some(true)
        || value
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|s| {
                let lower = s.to_ascii_lowercase();
                lower == "duplicate" || lower == "already_stored"
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_tool_text_structured_and_duplicate() {
        let direct =
            json!({"jsonrpc":"2.0","id":"run_1","result":{"schema":"gb.turn.v1","ok":true}});
        let outcome = interpret_rpc(&direct).unwrap();
        assert_eq!(outcome.envelope.unwrap()["schema"], "gb.turn.v1");

        let wrapped = json!({
            "result": {
                "content": [{"type":"text","text":"{\"schema\":\"gb.turn.v1\",\"envelope_id\":\"env\"}"}]
            }
        });
        assert!(interpret_rpc(&wrapped).unwrap().envelope.is_some());

        let structured = json!({"result":{"structuredContent":{"schema":"gb.turn.v1"}}});
        assert!(interpret_rpc(&structured).unwrap().envelope.is_some());

        let dup = json!({"error":{"code":-32000,"message":"duplicate run_id"}});
        assert!(interpret_rpc(&dup).unwrap().duplicate);

        assert!(matches!(
            interpret_rpc(&json!({"error":{"message":"nope"}})),
            Err(TransportError::Rpc)
        ));
        assert!(matches!(
            interpret_rpc(&json!({"result":{"isError":true,"content":[{"text":"boom"}]}})),
            Err(TransportError::Rpc)
        ));
    }

    #[test]
    fn http_timeout_and_roundtrip_shape() {
        use crate::body::{prepare_body, RunInput};
        use crate::key::AgentKey;
        use crate::seal::{seal_run, SealRequest};
        use chrono::{DateTime, Utc};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Instant;
        use x25519_dalek::{PublicKey, StaticSecret};

        let agent = AgentKey::from_seed(
            "tenant-test",
            "agent-test",
            [9u8; 32],
            DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            1,
        )
        .unwrap();
        let recip = StaticSecret::from([6u8; 32]);
        let recip_pub = PublicKey::from(&recip).to_bytes();
        let body = prepare_body(RunInput {
            tenant_id: "tenant-test".into(),
            user_id: "p_owner".into(),
            transcript: "hello".into(),
            ..RunInput::default()
        })
        .unwrap();
        let message = seal_run(SealRequest {
            body: &body,
            tenant_id: "tenant-test",
            user_id: "p_owner",
            run_id: "run_HTTP",
            seq: 1,
            sent_at: "2026-10-22T15:44:58Z",
            replay: false,
            agent: &agent,
            recipient_key_id: "cerveau-test",
            recipient_public: &recip_pub,
            randomness: None,
            account: None,
        })
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            thread::sleep(Duration::from_millis(800));
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        });
        let transport = HttpTransport::new(
            Some(format!("http://127.0.0.1:{port}/mcp")),
            "cerveau.run",
            None,
            None,
        );
        let started = Instant::now();
        let err = transport
            .call(&message, Duration::from_millis(200))
            .unwrap_err();
        assert!(
            matches!(err, TransportError::Timeout | TransportError::Unreachable),
            "{err:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = server.join();
    }
}
