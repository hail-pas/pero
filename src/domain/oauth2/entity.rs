use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::shared::error::AppError;

#[derive(Debug, sqlx::FromRow, Serialize, Clone)]
pub struct OAuth2Client {
    pub id: Uuid,
    pub app_id: Uuid,
    pub client_id: String,
    pub client_secret_hash: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuth2Client {
    pub fn verify_secret(&self, secret: &str) -> Result<bool, AppError> {
        bcrypt::verify(secret, &self.client_secret_hash)
            .map_err(|e| AppError::Internal(format!("Secret verify error: {e}")))
    }

    pub fn allows_grant_type(&self, grant_type: &str) -> bool {
        self.grant_types.iter().any(|value| value == grant_type)
    }
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct RefreshToken {
    pub id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub refresh_token: String,
    pub scopes: Vec<String>,
    pub auth_time: i64,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}
