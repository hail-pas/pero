pub fn random_hex_token() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}
