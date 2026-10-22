pub fn normalize_optional_string(value: Option<String>) -> Option<String> {
    let value = value?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

pub fn json_str_field(json: &serde_json::Value, key: &str) -> Option<String> {
    json.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

pub fn json_int_field(json: &serde_json::Value, key: &str) -> Option<String> {
    json.get(key)
        .and_then(|v| v.as_i64())
        .map(|n| n.to_string())
}

pub fn canonical_rate_limit_key(value: &str) -> String {
    let lower = value.trim().to_ascii_lowercase();
    if looks_like_phone_identifier(&lower) {
        lower
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n' | '-' | '(' | ')' | '.'))
            .collect()
    } else {
        lower
    }
}

fn looks_like_phone_identifier(value: &str) -> bool {
    let mut has_digit = false;
    for (index, ch) in value.chars().enumerate() {
        if ch.is_ascii_digit() {
            has_digit = true;
            continue;
        }
        if index == 0 && ch == '+' {
            continue;
        }
        if matches!(ch, ' ' | '\t' | '\r' | '\n' | '-' | '(' | ')' | '.') {
            continue;
        }
        return false;
    }
    has_digit
}
