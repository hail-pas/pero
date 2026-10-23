use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

pub struct PasswordHashResult {
    pub hash: String,
    pub algorithm: String,
}

pub fn hash_password(password: &str) -> Result<PasswordHashResult, argon2::password_hash::Error> {
    let salt = rand::random::<[u8; 16]>();
    let params = Params::new(65536, 3, 4, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_hash: PasswordHash = argon2.hash_password_with_salt(password.as_bytes(), &salt)?;
    Ok(PasswordHashResult {
        hash: salt_hash.to_string(),
        algorithm: "argon2id".to_owned(),
    })
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}
