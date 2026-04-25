use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationErrors};

use crate::shared::patch::Patch;
use crate::shared::validation;

#[derive(Debug, sqlx::FromRow, Serialize, Clone, ToSchema)]
pub struct SocialProvider {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct SocialProviderPublic {
    pub name: String,
    pub display_name: String,
}

impl From<&SocialProvider> for SocialProviderPublic {
    fn from(p: &SocialProvider) -> Self {
        Self {
            name: p.name.clone(),
            display_name: p.display_name.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateSocialProviderRequest {
    #[validate(length(min = 1, max = 32))]
    pub name: String,
    #[validate(length(min = 1, max = 64))]
    pub display_name: String,
    #[validate(length(min = 1, max = 255))]
    pub client_id: String,
    #[validate(length(min = 1))]
    pub client_secret: String,
    #[validate(length(min = 1))]
    #[validate(custom(function = "crate::shared::validation::validate_url"))]
    pub authorize_url: String,
    #[validate(length(min = 1))]
    #[validate(custom(function = "crate::shared::validation::validate_url"))]
    pub token_url: String,
    #[validate(length(min = 1))]
    #[validate(custom(function = "crate::shared::validation::validate_url"))]
    pub userinfo_url: String,
    #[serde(default)]
    #[validate(custom(function = "crate::shared::validation::validate_non_empty_items"))]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSocialProviderRequest {
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub display_name: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub client_id: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub client_secret: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub authorize_url: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub token_url: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub userinfo_url: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub scopes: Patch<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<bool>)]
    pub enabled: Patch<bool>,
}

impl Validate for UpdateSocialProviderRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        self.display_name
            .validate_required("display_name", &mut errors, |v| {
                validation::validate_length(v, 1, 64)
            });
        self.client_id
            .validate_required("client_id", &mut errors, |v| {
                validation::validate_length(v, 1, 255)
            });
        self.client_secret
            .validate_required("client_secret", &mut errors, |v| {
                validation::validate_length(v, 1, 4096)
            });
        self.authorize_url
            .validate_required("authorize_url", &mut errors, |v| {
                validation::validate_url(v)
            });
        self.token_url
            .validate_required("token_url", &mut errors, |v| validation::validate_url(v));
        self.userinfo_url
            .validate_required("userinfo_url", &mut errors, |v| validation::validate_url(v));
        self.scopes.validate_required("scopes", &mut errors, |v| {
            validation::validate_non_empty_items(v)
        });
        self.enabled
            .validate_required("enabled", &mut errors, |_| Ok(()));
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
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

impl From<SocialProvider> for SocialProviderDTO {
    fn from(p: SocialProvider) -> Self {
        Self {
            id: p.id,
            name: p.name,
            display_name: p.display_name,
            client_id: p.client_id,
            authorize_url: p.authorize_url,
            token_url: p.token_url,
            userinfo_url: p.userinfo_url,
            scopes: p.scopes,
            enabled: p.enabled,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserInfo {
    pub provider: String,
    pub provider_uid: String,
    pub email: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}
