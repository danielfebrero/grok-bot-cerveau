/// Maximum length of a `run_id`, in bytes.
pub const RUN_ID_MAX: usize = 80;
/// Maximum length of a `key_id`, in bytes.
pub const KEY_ID_MAX: usize = 128;
/// Maximum length of an agent id, in bytes.
pub const AGENT_ID_MAX: usize = 64;

/// ASCII token: non-empty, at most `max` bytes, charset `[A-Za-z0-9_-]`.
pub fn is_token(value: &str, max: usize) -> bool {
    let n = value.len();
    (1..=max).contains(&n)
        && value
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

pub fn is_run_id(value: &str) -> bool {
    is_token(value, RUN_ID_MAX)
}

pub fn is_key_id(value: &str) -> bool {
    is_token(value, KEY_ID_MAX)
}

pub(crate) fn is_agent_id(value: &str) -> bool {
    let n = value.len();
    if !(1..=AGENT_ID_MAX).contains(&n) || value.contains("..") {
        return false;
    }
    if value.starts_with(':') || value.ends_with(':') || value.starts_with('-') {
        return false;
    }
    value
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b':'))
}

pub(crate) fn is_sent_at(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20 {
        return false;
    }
    let marks = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if marks.iter().any(|(i, c)| b[*i] != *c) {
        return false;
    }
    b.iter()
        .enumerate()
        .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || c.is_ascii_digit())
}

pub(crate) fn is_safe_actor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 200 && !value.chars().any(|c| c.is_control() || c == '|')
}

/// A direct send of `seq` is allowed only when no queued seq is older.
pub(crate) fn may_send_direct(queued_seqs: &[u64], seq: u64) -> bool {
    !queued_seqs.iter().any(|other| *other < seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_grammar() {
        assert!(is_run_id("run_01HZABCDEFGHJKMNPQRSTVWXYZ"));
        assert!(is_key_id("gb-agent-test-202610"));
        assert!(is_key_id(&"a".repeat(KEY_ID_MAX)));
        assert!(!is_run_id(""));
        assert!(!is_run_id("run id"));
        assert!(!is_run_id("run:1"));
        assert!(!is_run_id("run.1"));
        assert!(!is_run_id("café"));
        assert!(!is_run_id(&"a".repeat(RUN_ID_MAX + 1)));
        assert!(!is_key_id(&"k".repeat(KEY_ID_MAX + 1)));
        assert!(!is_key_id("cerveau.2026"));
    }

    #[test]
    fn sent_at_and_actor() {
        assert!(is_sent_at("2026-10-22T15:44:58Z"));
        assert!(!is_sent_at("2026-10-22T15:44:58.000Z"));
        assert!(!is_sent_at("2026-10-22 15:44:58Z"));
        assert!(is_safe_actor("gb:agent-test"));
        assert!(!is_safe_actor("bad|actor"));
        assert!(!is_safe_actor("bad\nactor"));
    }

    #[test]
    fn direct_send_requires_no_older_seq() {
        assert!(may_send_direct(&[1], 1));
        assert!(may_send_direct(&[2, 3], 2));
        assert!(!may_send_direct(&[1, 2], 2));
        assert!(!may_send_direct(&[1, 2, 3], 3));
        assert!(may_send_direct(&[], 1));
    }
}
