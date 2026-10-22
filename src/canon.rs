use std::cmp::Ordering;

use serde_json::Value;

/// Canonical JSON (`gb.canon.v1`) used for envelope body hashes and sealed plaintext.
///
/// Objects keys are sorted by UTF-16 code unit order. Strings use `serde_json`
/// escaping (controls, quotes, and backslashes escaped; solidus and non-ASCII
/// left as UTF-8). Numbers use the `serde_json` lexical form, with integers
/// emitted without a fraction. There is no insignificant whitespace.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                out.push_str(&serde_json::to_string(n).unwrap_or_else(|_| "null".to_string()));
            }
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string encodes")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| cmp_utf16(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("key encodes"));
                out.push(':');
                write_value(out, &map[*key]);
            }
            out.push('}');
        }
    }
}

fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_keeps_array_order() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": "x"})),
            r#"{"a":"x","b":1}"#
        );
        assert_eq!(canonical_json(&json!([2, 1])), "[2,1]");
        assert_eq!(
            canonical_json(&json!({"é": 1, "a": 2})),
            "{\"a\":2,\"é\":1}"
        );
    }

    #[test]
    fn utf16_order_puts_supplementary_before_high_bmp() {
        let v = json!({ "\u{FFFD}": 1, "\u{1F600}": 2 });
        let c = canonical_json(&v);
        let emoji = c.find('\u{1F600}').unwrap();
        let replacement = c.find('\u{FFFD}').unwrap();
        assert!(emoji < replacement);
    }

    #[test]
    fn string_escaping_matches_json_not_hex_escapes_for_newline() {
        assert_eq!(canonical_json(&json!("a\"b")), r#""a\"b""#);
        assert_eq!(canonical_json(&json!("é")), "\"é\"");
        assert_eq!(canonical_json(&json!("a/b")), "\"a/b\"");
        assert_eq!(canonical_json(&json!("\n")), r#""\n""#);
        assert_eq!(
            canonical_json(&json!(1.5)),
            serde_json::to_string(&json!(1.5)).unwrap()
        );
    }
}
