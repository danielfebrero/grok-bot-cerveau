use std::sync::OnceLock;

use regex::Regex;

/// Optional detectors. Both are off unless the caller asks for them.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactOptions {
    pub emails: bool,
    pub phones: bool,
}

/// Span redaction result. The original text is kept around each masked match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    pub text: String,
    pub hits: Vec<String>,
}

#[derive(Clone, Copy)]
enum Repl {
    Whole,
    UrlPassword,
    Assignment,
}

struct Rule {
    kind: &'static str,
    priority: u8,
    regex: Regex,
    repl: Repl,
    optional: Optional,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Optional {
    Always,
    Email,
    Phone,
}

/// Masks secret spans in place. A 40-character hex string (a commit SHA) becomes
/// one marker; the rest of the message stays.
pub fn redact_text(input: &str, opts: &RedactOptions) -> Redaction {
    let rules = rules();
    let mut out = String::with_capacity(input.len());
    let mut hits = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        let Some(hit) = find_earliest(input, pos, rules, opts) else {
            out.push_str(&input[pos..]);
            break;
        };
        out.push_str(&input[pos..hit.start]);
        out.push_str(&hit.replacement);
        if !hits.iter().any(|h: &String| h == hit.kind) {
            hits.push(hit.kind.to_string());
        }
        pos = hit.end;
    }
    Redaction { text: out, hits }
}

struct Hit<'a> {
    start: usize,
    end: usize,
    kind: &'a str,
    replacement: String,
}

fn find_earliest<'a>(
    text: &str,
    pos: usize,
    rules: &'a [Rule],
    opts: &RedactOptions,
) -> Option<Hit<'a>> {
    let mut best: Option<Hit<'a>> = None;
    for rule in rules {
        if !rule_enabled(rule.optional, opts) {
            continue;
        }
        for caps in rule.regex.captures_iter(&text[pos..]) {
            let m = caps.get(0).expect("full match");
            let start = pos + m.start();
            let end = pos + m.end();
            let worse = best.as_ref().is_some_and(|b| {
                start > b.start || (start == b.start && rule.priority >= b_priority(b, rules))
            });
            if worse {
                continue;
            }
            // Only the first match of this rule can be the leftmost; later ones start later.
            let replacement = match rule.repl {
                Repl::Whole => format!("[REDACTED:{}]", rule.kind),
                Repl::UrlPassword => {
                    let prefix = caps.name("prefix").map(|c| c.as_str()).unwrap_or("");
                    format!("{prefix}[REDACTED:url_password]@")
                }
                Repl::Assignment => {
                    let key = caps.name("key").map(|c| c.as_str()).unwrap_or("");
                    format!("{key}[REDACTED:assignment]")
                }
            };
            best = Some(Hit {
                start,
                end,
                kind: rule.kind,
                replacement,
            });
            break;
        }
    }
    best
}

fn b_priority(hit: &Hit<'_>, rules: &[Rule]) -> u8 {
    rules
        .iter()
        .find(|r| r.kind == hit.kind)
        .map(|r| r.priority)
        .unwrap_or(255)
}

fn rule_enabled(optional: Optional, opts: &RedactOptions) -> bool {
    match optional {
        Optional::Always => true,
        Optional::Email => opts.emails,
        Optional::Phone => opts.phones,
    }
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let compile = |pattern: &str| Regex::new(pattern).expect("redaction pattern compiles");
        vec![
            Rule {
                kind: "private_key",
                priority: 0,
                regex: compile(
                    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)-----END [A-Z0-9 ]*PRIVATE KEY-----",
                ),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "url_password",
                priority: 1,
                regex: compile(
                    r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)(?P<pass>[^@\s/]+)@",
                ),
                repl: Repl::UrlPassword,
                optional: Optional::Always,
            },
            Rule {
                kind: "jwt",
                priority: 2,
                regex: compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "github_token",
                priority: 3,
                regex: compile(
                    r"gh[pours]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}",
                ),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "slack_token",
                priority: 4,
                regex: compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "aws_access_key",
                priority: 5,
                regex: compile(r"AKIA[0-9A-Z]{16}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "xai_key",
                priority: 6,
                regex: compile(r"xai-[A-Za-z0-9_-]{16,}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "sk_key",
                priority: 7,
                regex: compile(r"sk-[A-Za-z0-9_-]{16,}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "bearer",
                priority: 8,
                regex: compile(r"(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]{8,}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "assignment",
                priority: 9,
                regex: compile(
                    r"(?i)(?P<key>\b(?:password|passwd|secret|api_key|apikey|access_token|token)\b\s*[:=]\s*)(?P<val>\S+)",
                ),
                repl: Repl::Assignment,
                optional: Optional::Always,
            },
            Rule {
                kind: "hex",
                priority: 10,
                regex: compile(r"[0-9A-Fa-f]{40,}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "base64",
                priority: 11,
                regex: compile(r"[A-Za-z0-9+/]{64,}={0,2}"),
                repl: Repl::Whole,
                optional: Optional::Always,
            },
            Rule {
                kind: "email",
                priority: 12,
                regex: compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
                repl: Repl::Whole,
                optional: Optional::Email,
            },
            Rule {
                kind: "phone",
                priority: 13,
                regex: compile(r"\+[0-9]{8,15}|\b[0-9]{3}[-. ][0-9]{3}[-. ][0-9]{4}\b"),
                repl: Repl::Whole,
                optional: Optional::Phone,
            },
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn off() -> RedactOptions {
        RedactOptions::default()
    }

    #[test]
    fn commit_sha_masks_only_the_span() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let text = format!("voir https://example.com/commit/{sha} merci");
        let red = redact_text(&text, &off());
        assert_eq!(
            red.text,
            "voir https://example.com/commit/[REDACTED:hex] merci".to_string()
        );
        assert_eq!(red.hits, vec!["hex".to_string()]);
        assert!(!red.text.contains(sha));
        assert!(red.text.contains("voir "));
        assert!(red.text.contains(" merci"));
    }

    #[test]
    fn short_hex_is_kept() {
        let red = redact_text(
            "color deadbeef and 39 chars 0123456789abcdef0123456789abcdef0123456 end",
            &off(),
        );
        assert!(red.text.contains("deadbeef"));
        assert!(red.text.contains("0123456789abcdef0123456789abcdef0123456"));
        assert!(red.hits.is_empty());
    }

    #[test]
    fn several_spans_keep_the_words_between() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let text = format!("avant {sha} milieu sk-abcdefghijklmnopqrstuvwxyz fin");
        let red = redact_text(&text, &off());
        assert!(red.text.starts_with("avant "));
        assert!(red.text.contains(" milieu "));
        assert!(red.text.ends_with(" fin"));
        assert!(!red.text.contains(sha));
        assert!(!red.text.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(red.hits, vec!["hex".to_string(), "sk_key".to_string()]);
    }

    #[test]
    fn tokens_urls_pem_jwt_and_assignment_are_spans() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----";
        let text = format!(
            "clé {pem} puis https://alice:s3cret@example.com/a et ghp_{} et {}",
            "A".repeat(36),
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
        );
        let red = redact_text(&text, &off());
        assert!(red.text.starts_with("clé "));
        assert!(red.text.contains("[REDACTED:private_key]"));
        assert!(red
            .text
            .contains("https://alice:[REDACTED:url_password]@example.com/a"));
        assert!(red.text.contains("[REDACTED:github_token]"));
        assert!(red.text.contains("[REDACTED:jwt]"));
        assert!(!red.text.contains("s3cret"));
        assert!(!red.text.contains("BEGIN PRIVATE KEY"));

        let assigned = redact_text("login password=hunter2 please", &off());
        assert_eq!(assigned.text, "login password=[REDACTED:assignment] please");

        let bearer = redact_text("Authorization: Bearer abcdefghijklmnop next", &off());
        assert_eq!(bearer.text, "Authorization: [REDACTED:bearer] next");
        assert!(bearer.text.contains("Authorization: "));
        assert!(bearer.text.contains(" next"));
    }

    #[test]
    fn prefix_tokens_and_optional_contacts() {
        let text = format!(
            "xai-{} github_pat_{} AKIA{} xoxb-{} blob {}",
            "a".repeat(20),
            "b".repeat(22),
            "C".repeat(16),
            "d".repeat(12),
            "Ag".repeat(32) + "+/=="
        );
        let red = redact_text(&text, &off());
        for kind in [
            "xai_key",
            "github_token",
            "aws_access_key",
            "slack_token",
            "base64",
        ] {
            assert!(red.hits.iter().any(|h| h == kind), "{kind}");
        }
        assert!(red.text.contains(" blob "));

        let contact = "mail ada@example.com call +33612345678";
        let plain = redact_text(contact, &off());
        assert_eq!(plain.text, contact);
        let masked = redact_text(
            contact,
            &RedactOptions {
                emails: true,
                phones: true,
            },
        );
        assert_eq!(masked.text, "mail [REDACTED:email] call [REDACTED:phone]");
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact_text("see 0123456789abcdef0123456789abcdef01234567 now", &off());
        let twice = redact_text(&once.text, &off());
        assert_eq!(once.text, twice.text);
    }
}
