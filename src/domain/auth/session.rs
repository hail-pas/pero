use crate::shared::error::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySession {
    pub session_id: String,
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub previous_refresh_token_hash: Option<String>,
    pub created_at: i64,
    pub rotated_at: i64,
    pub device: String,
    pub location: String,
}

pub fn parse_session_id(refresh_token: &str) -> Result<&str, AppError> {
    refresh_token
        .split_once('.')
        .map(|(session_id, _)| session_id)
        .ok_or(AppError::Unauthorized)
}

pub fn hash_refresh_token(refresh_token: &str) -> String {
    crate::shared::utils::sha256_hex(refresh_token)
}

pub fn build_refresh_token(session_id: &str) -> String {
    let secret = crate::shared::utils::random_hex_token();
    format!("{session_id}.{secret}")
}
