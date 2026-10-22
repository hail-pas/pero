pub struct VerificationCode {
    pub code: String,
    pub nonce: String,
    pub code_hash: String,
}

pub fn generate_code() -> VerificationCode {
    let code = pero_utils::crypto::generate_code();
    let nonce = pero_utils::crypto::generate_nonce();
    let code_hash = pero_utils::crypto::sha256_hex(&code);
    VerificationCode {
        code,
        nonce,
        code_hash,
    }
}

pub fn expires_in(duration: time::Duration) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + duration
}

pub fn expires_in_seconds(seconds: u64) -> time::OffsetDateTime {
    expires_in(time::Duration::seconds(seconds as i64))
}
