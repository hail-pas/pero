use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::oauth::client_dto as domain;

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuth2ClientDTO {
    pub id: Uuid,
    pub app_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<domain::OAuth2ClientDTO> for OAuth2ClientDTO {
    fn from(d: domain::OAuth2ClientDTO) -> Self {
        Self {
            id: d.id,
            app_id: d.app_id,
            client_id: d.client_id,
            client_name: d.client_name,
            redirect_uris: d.redirect_uris,
            grant_types: d.grant_types,
            scopes: d.scopes,
            post_logout_redirect_uris: d.post_logout_redirect_uris,
            enabled: d.enabled,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateClientResponse {
    pub client: OAuth2ClientDTO,
    pub client_secret: String,
}

impl From<domain::CreateClientResponse> for CreateClientResponse {
    fn from(d: domain::CreateClientResponse) -> Self {
        Self {
            client: d.client.into(),
            client_secret: d.client_secret,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateClientRequest {
    pub app_id: Uuid,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
}

impl From<CreateClientRequest> for domain::CreateClientRequest {
    fn from(r: CreateClientRequest) -> Self {
        Self {
            app_id: r.app_id,
            client_name: r.client_name,
            redirect_uris: r.redirect_uris,
            grant_types: r.grant_types,
            scopes: r.scopes,
            post_logout_redirect_uris: r.post_logout_redirect_uris,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClientRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuth2TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

impl From<domain::TokenResponse> for OAuth2TokenResponse {
    fn from(d: domain::TokenResponse) -> Self {
        Self {
            access_token: d.access_token,
            token_type: d.token_type,
            expires_in: d.expires_in,
            refresh_token: d.refresh_token,
            id_token: d.id_token,
            scope: d.scope,
        }
    }
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub login_hint: Option<String>,
    pub provider: Option<String>,
}
