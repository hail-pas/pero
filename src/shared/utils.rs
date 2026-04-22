pub fn random_hex_token() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

pub fn sha256_hex(value: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(value.as_bytes()))
}
