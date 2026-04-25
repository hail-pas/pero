use serde::Deserialize;

pub fn empty_string_as_none<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.filter(|s| !s.trim().is_empty()))
}

pub fn random_hex_token() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

pub fn sha256_hex(value: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(value.as_bytes()))
}

pub fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}
