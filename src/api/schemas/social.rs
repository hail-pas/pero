use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::federation::entity as domain;

#[derive(Debug, Serialize, ToSchema)]
pub struct SocialProviderPublicDTO {
    pub name: String,
    pub display_name: String,
}

impl From<domain::SocialProviderPublic> for SocialProviderPublicDTO {
    fn from(d: domain::SocialProviderPublic) -> Self {
        Self {
            name: d.name,
            display_name: d.display_name,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SocialProviderDTO {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<domain::SocialProviderDTO> for SocialProviderDTO {
    fn from(d: domain::SocialProviderDTO) -> Self {
        Self {
            id: d.id,
            name: d.name,
            display_name: d.display_name,
            client_id: d.client_id,
            authorize_url: d.authorize_url,
            token_url: d.token_url,
            userinfo_url: d.userinfo_url,
            scopes: d.scopes,
            enabled: d.enabled,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSocialProviderRequest {
    pub name: String,
    pub display_name: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl From<CreateSocialProviderRequest> for domain::CreateSocialProviderRequest {
    fn from(r: CreateSocialProviderRequest) -> Self {
        Self {
            name: r.name,
            display_name: r.display_name,
            client_id: r.client_id,
            client_secret: r.client_secret,
            authorize_url: r.authorize_url,
            token_url: r.token_url,
            userinfo_url: r.userinfo_url,
            scopes: r.scopes,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSocialProviderRequest {
    pub display_name: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub authorize_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub enabled: Option<bool>,
}
