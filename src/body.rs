use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::id::{is_tenant_id, is_user_id};
use crate::redact::{self, RedactOptions};

pub const BODY_SCHEMA: &str = "gb.run.body.v2";

const TRIGGER_TEXT_MAX: usize = 500;
const DELTA_MAX: usize = 16;
const DELTA_TEXT_MAX: usize = 1200;
const TOOLS_MAX: usize = 8;
const TOOL_SUMMARY_MAX: usize = 400;
const DECISIONS_MAX: usize = 20;
const DECISION_FACT_MAX: usize = 400;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttributionError {
    #[error("message is missing an explicit from")]
    MissingFrom,
    #[error("role user requires human_typed and an explicit from")]
    UserRequiresHuman,
    #[error("the user id is only valid on text that user typed in this turn")]
    UserSpoof,
    #[error("human from does not match the configured user")]
    UserMismatch,
    #[error("tenant id or user id is not an ASCII token")]
    Identity,
    #[error("sender is empty, too long, or contains control characters")]
    BadFrom,
    #[error("message text is missing")]
    MissingText,
    #[error("unknown role or origin")]
    Unknown,
    #[error(
        "transcript line {line} is not host JSONL (expected role user|assistant|tool and message.content)"
    )]
    BadTranscript { line: usize },
}

/// Who produced a turn message. The wire role is derived from this, not chosen freely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageOrigin {
    /// Text the configured user typed during this turn.
    ///
    /// `claimed_from`, when set, must equal that user id. The wire `from`
    /// is always the user id, never a display name.
    Human { claimed_from: Option<String> },
    /// Another agent, relayed into this turn.
    RelayedAgent { from: String },
    /// External mention or inbound sender.
    Inbound { from: String },
    /// Tool output. `from` is the tool's real name.
    Tool { from: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnMessage {
    pub origin: MessageOrigin,
    pub text: String,
    pub ref_id: Option<String>,
    pub at: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RunInput {
    pub tenant_id: String,
    pub user_id: String,
    /// Verbatim turn text. A host turn is JSONL (`role` + `message.content` per line).
    pub transcript: String,
    pub prev_envelope_id: Option<String>,
    pub trigger: Option<TurnMessage>,
    pub messages: Vec<TurnMessage>,
    pub tool_results: Vec<ToolResult>,
    pub decisions: Vec<Decision>,
    pub redact_emails: bool,
    pub redact_phones: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolResult {
    pub tool: String,
    pub status: String,
    pub summary: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub fact: String,
    pub kind: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trigger {
    pub kind: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    pub text: String,
    pub untrusted_user_input: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptEntry {
    pub role: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    pub text: String,
    pub untrusted_user_input: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionReport {
    pub applied: bool,
    pub hits: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunBody {
    pub schema: String,
    pub tenant_id: String,
    /// User id local, pour l'attribution en mémoire. Absent du clair scellé.
    #[serde(default, skip_serializing)]
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_envelope_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
    /// Verbatim turn text. A host turn is JSONL (`role` + `message.content` per line).
    pub transcript: String,
    pub transcript_delta: Vec<TranscriptEntry>,
    pub tool_results: Vec<ToolResult>,
    pub decisions: Vec<Decision>,
    pub redaction: RedactionReport,
}

struct Projected {
    role: &'static str,
    kind: &'static str,
    from: String,
    untrusted_user_input: bool,
}

pub fn prepare_body(input: RunInput) -> Result<RunBody, AttributionError> {
    if !is_tenant_id(&input.tenant_id) || !is_user_id(&input.user_id) {
        return Err(AttributionError::Identity);
    }
    let user_id = input.user_id.clone();
    let opts = RedactOptions {
        emails: input.redact_emails,
        phones: input.redact_phones,
    };
    let mut hits = Vec::new();
    let mut truncated = false;
    let transcript = redact_transcript(&input.transcript, &opts, &mut hits)?;

    let trigger = match input.trigger {
        Some(message) => {
            let projected = project(&message.origin, &user_id)?;
            let (text, cut) = clip(
                &redact_prose(&message.text, &opts, &mut hits),
                TRIGGER_TEXT_MAX,
            );
            truncated |= cut;
            Some(Trigger {
                kind: projected.kind.to_string(),
                from: projected.from,
                ref_id: message.ref_id,
                at: message.at,
                text,
                untrusted_user_input: projected.untrusted_user_input,
            })
        }
        None => None,
    };

    let mut entries = Vec::new();
    for message in input.messages {
        let projected = project(&message.origin, &user_id)?;
        let (text, cut) = clip(
            &redact_prose(&message.text, &opts, &mut hits),
            DELTA_TEXT_MAX,
        );
        truncated |= cut;
        entries.push(TranscriptEntry {
            role: projected.role.to_string(),
            from: projected.from,
            ref_id: message.ref_id,
            at: message.at,
            text,
            untrusted_user_input: projected.untrusted_user_input,
        });
    }
    if entries.len() > DELTA_MAX {
        let drop_n = entries.len() - DELTA_MAX;
        entries.drain(0..drop_n);
        truncated = true;
    }

    let mut tools = input.tool_results;
    if tools.len() > TOOLS_MAX {
        let drop_n = tools.len() - TOOLS_MAX;
        tools.drain(0..drop_n);
        truncated = true;
    }
    for tool in &mut tools {
        let (summary, cut) = clip(
            &redact_prose(&tool.summary, &opts, &mut hits),
            TOOL_SUMMARY_MAX,
        );
        tool.summary = summary;
        truncated |= cut;
    }

    let mut decisions = input.decisions;
    if decisions.len() > DECISIONS_MAX {
        let drop_n = decisions.len() - DECISIONS_MAX;
        decisions.drain(0..drop_n);
        truncated = true;
    }
    for decision in &mut decisions {
        let (fact, cut) = clip(
            &redact_prose(&decision.fact, &opts, &mut hits),
            DECISION_FACT_MAX,
        );
        decision.fact = fact;
        truncated |= cut;
    }

    Ok(RunBody {
        schema: BODY_SCHEMA.to_string(),
        tenant_id: input.tenant_id,
        user_id,
        prev_envelope_id: input.prev_envelope_id,
        trigger,
        transcript,
        transcript_delta: entries,
        tool_results: tools,
        decisions,
        redaction: RedactionReport {
            applied: true,
            hits,
            truncated,
        },
    })
}

pub fn parse_messages(value: &Value, user_id: &str) -> Result<Vec<TurnMessage>, AttributionError> {
    let items = value.as_array().ok_or(AttributionError::Unknown)?;
    items
        .iter()
        .map(|item| parse_message(item, user_id))
        .collect()
}

pub fn parse_message(value: &Value, user_id: &str) -> Result<TurnMessage, AttributionError> {
    let text = value
        .get("text")
        .and_then(Value::as_str)
        .ok_or(AttributionError::MissingText)?
        .to_string();
    let ref_id = optional_string(value, "ref_id")?;
    let at = optional_string(value, "at")?;
    let origin = if let Some(origin) = value.get("origin").and_then(Value::as_str) {
        match origin {
            "human" => MessageOrigin::Human {
                claimed_from: optional_from(value)?,
            },
            "relayed_agent" => MessageOrigin::RelayedAgent {
                from: require_from(value)?,
            },
            "inbound" => MessageOrigin::Inbound {
                from: require_from(value)?,
            },
            "tool" => MessageOrigin::Tool {
                from: require_from(value)?,
            },
            _ => return Err(AttributionError::Unknown),
        }
    } else if let Some(role) = value.get("role").and_then(Value::as_str) {
        match role {
            "user" => {
                let human = value
                    .get("human_typed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !human {
                    return Err(AttributionError::UserRequiresHuman);
                }
                MessageOrigin::Human {
                    claimed_from: optional_from(value)?,
                }
            }
            "agent" => MessageOrigin::RelayedAgent {
                from: require_from(value)?,
            },
            "inbound" => MessageOrigin::Inbound {
                from: require_from(value)?,
            },
            "tool" => MessageOrigin::Tool {
                from: require_from(value)?,
            },
            _ => return Err(AttributionError::Unknown),
        }
    } else {
        return Err(AttributionError::Unknown);
    };
    project(&origin, user_id)?;
    Ok(TurnMessage {
        origin,
        text,
        ref_id,
        at,
    })
}

fn project(origin: &MessageOrigin, user_id: &str) -> Result<Projected, AttributionError> {
    if !is_user_id(user_id) {
        return Err(AttributionError::Identity);
    }
    match origin {
        MessageOrigin::Human { claimed_from } => {
            if let Some(claimed) = claimed_from {
                let claimed = clean_from(claimed)?;
                if claimed != user_id {
                    return Err(AttributionError::UserMismatch);
                }
            }
            Ok(Projected {
                role: "user",
                kind: "user_message",
                from: user_id.to_string(),
                untrusted_user_input: false,
            })
        }
        MessageOrigin::RelayedAgent { from } => Ok(Projected {
            role: "agent",
            kind: "agent",
            from: normalize_other(from, user_id)?,
            untrusted_user_input: true,
        }),
        MessageOrigin::Inbound { from } => Ok(Projected {
            role: "inbound",
            kind: "inbound",
            from: normalize_other(from, user_id)?,
            untrusted_user_input: true,
        }),
        MessageOrigin::Tool { from } => Ok(Projected {
            role: "tool",
            kind: "tool",
            from: normalize_other(from, user_id)?,
            untrusted_user_input: false,
        }),
    }
}

fn normalize_other(raw: &str, user_id: &str) -> Result<String, AttributionError> {
    let from = clean_from(raw)?;
    if from.eq_ignore_ascii_case(user_id) {
        Err(AttributionError::UserSpoof)
    } else {
        Ok(from)
    }
}

fn clean_from(raw: &str) -> Result<String, AttributionError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > 200
        || trimmed.chars().any(|c| c.is_control())
    {
        return Err(AttributionError::BadFrom);
    }
    Ok(trimmed.to_string())
}

fn optional_from(value: &Value) -> Result<Option<String>, AttributionError> {
    match value.get("from") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Err(AttributionError::MissingFrom),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(AttributionError::BadFrom),
    }
}

fn require_from(value: &Value) -> Result<String, AttributionError> {
    match value.get("from") {
        None | Some(Value::Null) => Err(AttributionError::MissingFrom),
        Some(Value::String(s)) if s.trim().is_empty() => Err(AttributionError::MissingFrom),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(AttributionError::BadFrom),
    }
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>, AttributionError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(AttributionError::Unknown),
    }
}

fn redact_prose(text: &str, opts: &RedactOptions, hits: &mut Vec<String>) -> String {
    let red = redact::redact_text(text, opts);
    for hit in red.hits {
        if !hits.iter().any(|h| h == &hit) {
            hits.push(hit);
        }
    }
    red.text
}

/// Host JSONL is redacted inside JSON strings so a span cannot swallow `"` or `}`.
/// Prose stays a single span scan. A slice that looks like host JSONL but is not
/// valid is refused; plain text is left alone.
fn redact_transcript(
    text: &str,
    opts: &RedactOptions,
    hits: &mut Vec<String>,
) -> Result<String, AttributionError> {
    if !looks_like_host_jsonl(text) {
        return Ok(redact_prose(text, opts, hits));
    }
    let mut out = String::with_capacity(text.len());
    let mut line_no = 1usize;
    let mut rest = text;
    while !rest.is_empty() {
        let (raw_line, nl, next) = split_first_line(rest);
        let content = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let cr = if content.len() == raw_line.len() {
            ""
        } else {
            "\r"
        };
        let trimmed = content.trim();
        if trimmed.is_empty() {
            out.push_str(raw_line);
        } else {
            if parse_host_line(trimmed).is_err() {
                return Err(AttributionError::BadTranscript { line: line_no });
            }
            let Some(start) = content.find(trimmed) else {
                return Err(AttributionError::BadTranscript { line: line_no });
            };
            let redacted = redact_json_strings(trimmed, opts, hits)
                .map_err(|_| AttributionError::BadTranscript { line: line_no })?;
            if parse_host_line(&redacted).is_err() {
                return Err(AttributionError::BadTranscript { line: line_no });
            }
            out.push_str(&content[..start]);
            out.push_str(&redacted);
            out.push_str(&content[start + trimmed.len()..]);
            out.push_str(cr);
        }
        out.push_str(nl);
        rest = next;
        line_no += 1;
    }
    Ok(out)
}

fn looks_like_host_jsonl(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .is_some_and(|line| {
            line.starts_with('{') && line.contains("\"role\"") && line.contains("\"message\"")
        })
}

fn parse_host_line(line: &str) -> Result<(), ()> {
    let value: Value = serde_json::from_str(line).map_err(|_| ())?;
    let role = value.get("role").and_then(Value::as_str).ok_or(())?;
    if !matches!(role, "user" | "assistant" | "tool") {
        return Err(());
    }
    match value.pointer("/message/content") {
        Some(Value::Array(_)) => Ok(()),
        _ => Err(()),
    }
}

fn split_first_line(text: &str) -> (&str, &str, &str) {
    match text.find('\n') {
        Some(i) => (&text[..i], &text[i..i + 1], &text[i + 1..]),
        None => (text, "", ""),
    }
}

fn redact_json_strings(
    line: &str,
    opts: &RedactOptions,
    hits: &mut Vec<String>,
) -> Result<String, ()> {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        out.push_str(&rest[..start]);
        let (raw, next) = take_json_string(&rest[start..])?;
        let decoded: String = serde_json::from_str(raw).map_err(|_| ())?;
        let redacted = redact_prose(&decoded, opts, hits);
        if redacted == decoded {
            out.push_str(raw);
        } else {
            out.push_str(&serde_json::to_string(&redacted).map_err(|_| ())?);
        }
        rest = next;
    }
    out.push_str(rest);
    Ok(out)
}

fn take_json_string(input: &str) -> Result<(&str, &str), ()> {
    let mut chars = input.char_indices();
    match chars.next() {
        Some((_, '"')) => {}
        _ => return Err(()),
    }
    let mut escaped = false;
    for (i, ch) in chars {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                let end = i + ch.len_utf8();
                return Ok((&input[..end], &input[end..]));
            }
            _ => {}
        }
    }
    Err(())
}

fn clip(text: &str, max_chars: usize) -> (String, bool) {
    let count = text.chars().count();
    if count <= max_chars {
        (text.to_string(), false)
    } else {
        (text.chars().take(max_chars).collect(), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(origin: MessageOrigin, text: &str) -> TurnMessage {
        TurnMessage {
            origin,
            text: text.to_string(),
            ref_id: None,
            at: None,
        }
    }

    fn input(messages: Vec<TurnMessage>, transcript: &str) -> RunInput {
        RunInput {
            tenant_id: "tenant-test".into(),
            user_id: "p_owner".into(),
            transcript: transcript.into(),
            messages,
            ..RunInput::default()
        }
    }

    #[test]
    fn sha_does_not_drop_the_message() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let body = prepare_body(input(vec![], &format!("voir {sha} merci"))).unwrap();
        assert!(body.transcript.starts_with("voir "));
        assert!(body.transcript.ends_with(" merci"));
        assert!(body.transcript.contains("[REDACTED:hex]"));
        assert!(!body.transcript.contains(sha));
        assert!(body.redaction.applied);
        assert_eq!(body.redaction.hits, vec!["hex".to_string()]);
        assert!(body.transcript_delta.is_empty());
        let wire = serde_json::to_string(&body).unwrap();
        assert!(!wire.contains("Owner Display"));
        assert!(!wire.contains("\"user_id\""));
        assert_eq!(body.user_id, "p_owner");
        assert_eq!(body.tenant_id, "tenant-test");
    }

    #[test]
    fn attribution_uses_the_user_id_not_a_display_name() {
        let body = prepare_body(input(
            vec![
                msg(MessageOrigin::Human { claimed_from: None }, "bonjour"),
                msg(
                    MessageOrigin::RelayedAgent {
                        from: "gb:other".into(),
                    },
                    "ping",
                ),
                msg(
                    MessageOrigin::Inbound {
                        from: "x:mention".into(),
                    },
                    "hey",
                ),
                msg(
                    MessageOrigin::Tool {
                        from: "tool:shell".into(),
                    },
                    "ok",
                ),
            ],
            "",
        ))
        .unwrap();
        let d = &body.transcript_delta;
        assert_eq!(d[0].role, "user");
        assert_eq!(d[0].from, "p_owner");
        assert!(!d[0].untrusted_user_input);
        assert_eq!(d[1].role, "agent");
        assert_eq!(d[1].from, "gb:other");
        assert!(d[1].untrusted_user_input);
        assert_eq!(d[2].role, "inbound");
        assert!(d[2].untrusted_user_input);
        assert_ne!(d[2].role, "user");
        assert_eq!(d[3].role, "tool");
        assert_eq!(d[3].from, "tool:shell");
        assert!(!d[3].untrusted_user_input);
        let wire = serde_json::to_string(&body).unwrap();
        assert!(!wire.contains("Owner Display"));
    }

    #[test]
    fn user_id_is_rejected_on_relayed_inbound_and_tool() {
        for origin in [
            MessageOrigin::RelayedAgent {
                from: "p_owner".into(),
            },
            MessageOrigin::Inbound {
                from: "P_OWNER".into(),
            },
            MessageOrigin::Tool {
                from: " p_owner ".into(),
            },
        ] {
            let err = prepare_body(input(vec![msg(origin, "x")], "")).unwrap_err();
            assert_eq!(err, AttributionError::UserSpoof);
        }
    }

    #[test]
    fn json_role_user_needs_human_typed_and_matches_the_user() {
        let missing = json!({"role": "user", "text": "hi"});
        assert_eq!(
            parse_message(&missing, "p_owner").unwrap_err(),
            AttributionError::UserRequiresHuman
        );
        let spoof =
            json!({"role": "user", "from": "someone-else", "human_typed": true, "text": "hi"});
        assert_eq!(
            parse_message(&spoof, "p_owner").unwrap_err(),
            AttributionError::UserMismatch
        );
        let agent_missing = json!({"role": "agent", "text": "hi"});
        assert_eq!(
            parse_message(&agent_missing, "p_owner").unwrap_err(),
            AttributionError::MissingFrom
        );
        let ok = parse_message(
            &json!({
                "role": "user",
                "human_typed": true,
                "text": "salut"
            }),
            "p_owner",
        )
        .unwrap();
        let body = prepare_body(input(vec![ok], "")).unwrap();
        assert_eq!(body.transcript_delta[0].from, "p_owner");
        assert!(!body.transcript_delta[0].untrusted_user_input);

        let inbound = parse_message(
            &json!({
                "origin": "inbound",
                "from": "x:m",
                "text": "hey",
                "untrusted_user_input": false
            }),
            "p_owner",
        )
        .unwrap();
        let body = prepare_body(input(vec![inbound], "")).unwrap();
        assert!(body.transcript_delta[0].untrusted_user_input);
        assert_eq!(body.transcript_delta[0].role, "inbound");
    }

    fn host_line(role: &str, blocks: &str) -> String {
        format!(r#"{{"role":"{role}","message":{{"content":[{blocks}]}}}}"#)
    }

    #[test]
    fn host_jsonl_keeps_lines_and_redacts_inside_strings() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let long = "mot ".repeat(400);
        assert!(long.chars().count() > DELTA_TEXT_MAX);
        let tool = host_line(
            "tool",
            &format!(
                r#"{{"type":"tool_result","tool_use_id":"toolu_abc","name":"Shell","result":"{long}"}}"#
            ),
        );
        let raw = format!(
            "{}\n{}\n{}\n",
            host_line(
                "user",
                &format!(r#"{{"type":"text","text":"voir {sha} merci"}}"#)
            ),
            host_line(
                "assistant",
                r#"{"type":"thinking","thinking":"note interne"},{"type":"tool_use","id":"toolu_abc","name":"Shell","input":{"command":"echo ok"}}"#
            ),
            tool,
        );
        let body = prepare_body(input(
            vec![msg(MessageOrigin::Human { claimed_from: None }, "salut")],
            &raw,
        ))
        .unwrap();
        assert_eq!(body.schema, BODY_SCHEMA);
        assert_eq!(body.transcript_delta.len(), 1);
        assert_eq!(body.transcript_delta[0].text, "salut");
        assert!(!body.transcript_delta[0].text.contains("mot mot"));
        assert!(body.transcript.contains(&long));
        assert!(body.transcript.contains("\"type\":\"thinking\""));
        assert!(body.transcript.contains("\"type\":\"tool_use\""));
        assert!(body.transcript.contains("toolu_abc"));
        assert!(!body.transcript.contains(sha));
        assert!(body.redaction.hits.iter().any(|hit| hit == "hex"));
        let lines: Vec<&str> = body
            .transcript
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            parse_host_line(line).expect(line);
        }
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["role"], "user");
        assert_eq!(
            first
                .pointer("/message/content/0/text")
                .and_then(Value::as_str),
            Some("voir [REDACTED:hex] merci")
        );
        let assistant: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(
            assistant.pointer("/message/content/0/type"),
            Some(&Value::String("thinking".into()))
        );
        assert_eq!(
            assistant.pointer("/message/content/1/name"),
            Some(&json!("Shell"))
        );
    }

    #[test]
    fn host_jsonl_without_secrets_is_verbatim() {
        let raw = format!(
            "{}\n\n{}\n",
            host_line("user", r#"{"type":"text","text":"bonjour"}"#),
            host_line(
                "tool",
                r#"{"type":"tool_result","tool_use_id":"toolu_abc","name":"Shell","result":"ok"}"#
            ),
        );
        let body = prepare_body(input(vec![], &raw)).unwrap();
        assert_eq!(body.transcript, raw);
        assert!(body.transcript_delta.is_empty());
        assert!(body.redaction.hits.is_empty());
    }

    #[test]
    fn host_jsonl_email_redaction_stays_json() {
        let raw = host_line(
            "user",
            r#"{"type":"text","text":"mail ada@example.com fin"}"#,
        );
        let mut kept = input(vec![], &raw);
        kept.redact_emails = false;
        let plain = prepare_body(kept).unwrap();
        assert_eq!(plain.transcript, raw);
        let mut masked = input(vec![], &raw);
        masked.redact_emails = true;
        let body = prepare_body(masked).unwrap();
        let value: Value = serde_json::from_str(body.transcript.trim()).unwrap();
        assert_eq!(
            value
                .pointer("/message/content/0/text")
                .and_then(Value::as_str),
            Some("mail [REDACTED:email] fin")
        );
        assert!(body.redaction.hits.iter().any(|hit| hit == "email"));
    }

    #[test]
    fn host_jsonl_assignment_does_not_swallow_delimiters() {
        // A prose scan would let `\S+` eat the closing quotes through EOL.
        let raw = host_line("assistant", r#"{"type":"text","text":"password=hunter2"}"#);
        let body = prepare_body(input(vec![], &raw)).unwrap();
        let value: Value = serde_json::from_str(body.transcript.trim()).unwrap();
        assert_eq!(value["role"], "assistant");
        assert_eq!(
            value
                .pointer("/message/content/0/text")
                .and_then(Value::as_str),
            Some("password=[REDACTED:assignment]")
        );
        assert!(!body.transcript.contains("hunter2"));
    }

    #[test]
    fn broken_host_jsonl_names_the_line() {
        let raw = format!(
            "{}\nnot json\n",
            host_line("user", r#"{"type":"text","text":"ok"}"#)
        );
        assert_eq!(
            prepare_body(input(vec![], &raw)).unwrap_err(),
            AttributionError::BadTranscript { line: 2 }
        );
        let bad_role = host_line("agent", r#"{"type":"text","text":"ok"}"#);
        assert_eq!(
            prepare_body(input(vec![], &bad_role)).unwrap_err(),
            AttributionError::BadTranscript { line: 1 }
        );
    }

    #[test]
    fn prose_transcript_is_not_forced_into_jsonl() {
        let body = prepare_body(input(vec![], "bonjour {role} message")).unwrap();
        assert_eq!(body.transcript, "bonjour {role} message");
        let blob = r#"{"hello":"world"}"#;
        let body = prepare_body(input(vec![], blob)).unwrap();
        assert_eq!(body.transcript, blob);
    }
}
