use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::shared::constants::oauth2::{self as oauth2_constants, scopes as oauth2_scopes};
use crate::shared::error::AppError;

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum CodeChallengeMethod {
    #[default]
    S256,
}

impl CodeChallengeMethod {
    pub fn as_str(&self) -> &'static str {
        "S256"
    }
}

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

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct OAuth2ClientDTO {
    pub id: Uuid,
    pub app_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<OAuth2Client> for OAuth2ClientDTO {
    fn from(c: OAuth2Client) -> Self {
        Self {
            id: c.id,
            app_id: c.app_id,
            client_id: c.client_id,
            client_name: c.client_name,
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.scopes,
            enabled: c.enabled,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateClientRequest {
    pub app_id: Uuid,
    #[validate(length(min = 1, max = 128))]
    pub client_name: String,
    #[validate(
        length(min = 1),
        custom(function = "crate::shared::validation::validate_redirect_uris")
    )]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_grant_types() -> Vec<String> {
    vec![oauth2_constants::GRANT_TYPE_AUTH_CODE.to_string()]
}

fn default_scopes() -> Vec<String> {
    vec![
        oauth2_scopes::OPENID.to_string(),
        oauth2_scopes::PROFILE.to_string(),
        oauth2_scopes::EMAIL.to_string(),
    ]
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateClientRequest {
    #[validate(length(min = 1, max = 128))]
    pub client_name: Option<String>,
    #[validate(custom(function = "crate::shared::validation::validate_redirect_uris"))]
    pub redirect_uris: Option<Vec<String>>,
    #[validate(length(min = 1))]
    pub scopes: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AuthorizeQuery {
    #[validate(length(min = 1))]
    pub client_id: String,
    #[validate(
        length(min = 1),
        custom(function = "crate::shared::validation::validate_redirect_uri")
    )]
    pub redirect_uri: String,
    pub response_type: ResponseType,
    pub scope: Option<String>,
    pub state: Option<String>,
    #[validate(length(min = 1, max = 128))]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    #[validate(length(max = 256))]
    pub code: Option<String>,
    #[validate(length(max = 2048))]
    pub redirect_uri: Option<String>,
    #[validate(length(max = 128))]
    pub client_id: Option<String>,
    #[validate(length(max = 256))]
    pub client_secret: Option<String>,
    #[validate(length(max = 256))]
    pub code_verifier: Option<String>,
    #[validate(length(max = 256))]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = OAuth2TokenResponse)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RevokeRequest {
    #[validate(length(min = 1, max = 256))]
    pub token: String,
    #[validate(length(max = 32))]
    pub token_type_hint: Option<String>,
    #[validate(length(max = 128))]
    pub client_id: Option<String>,
    #[validate(length(max = 256))]
    pub client_secret: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)] // REMARK: sqlx::FromRow requires all DB columns, some fields are read by token.rs
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
#[allow(dead_code)] // REMARK: sqlx::FromRow requires all DB columns, some fields are read by token.rs
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
