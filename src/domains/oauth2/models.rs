use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::shared::constants::oauth2::{self as oauth2_constants, scopes as oauth2_scopes};

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
    pub redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
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
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}
