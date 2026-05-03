use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationErrors};

use crate::shared::patch::FieldUpdate;
use crate::shared::validation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocialProviderName {
    Google,
    Github,
    Wechat,
    Apple,
    Microsoft,
    Qq,
}

impl SocialProviderName {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "google" => Some(Self::Google),
            "github" => Some(Self::Github),
            "wechat" => Some(Self::Wechat),
            "apple" => Some(Self::Apple),
            "microsoft" => Some(Self::Microsoft),
            "qq" => Some(Self::Qq),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Github => "github",
            Self::Wechat => "wechat",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::Qq => "qq",
        }
    }

    pub fn svg_icon(&self) -> &'static str {
        match self {
            Self::Google => {
                r##"<svg viewBox="0 0 24 24" width="20" height="20"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>"##
            }
            Self::Github => {
                r##"<svg viewBox="0 0 24 24" width="20" height="20"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z" fill="#24292f"/></svg>"##
            }
            Self::Wechat => {
                r##"<svg viewBox="0 0 24 24" width="20" height="20"><path d="M8.691 2.188C3.891 2.188 0 5.476 0 9.53c0 2.212 1.17 4.203 3.002 5.55a.59.59 0 0 1 .213.665l-.39 1.48c-.019.07-.048.141-.048.213 0 .163.13.295.29.295a.326.326 0 0 0 .167-.054l1.903-1.114a.864.864 0 0 1 .717-.098 10.16 10.16 0 0 0 2.837.403c.276 0 .543-.027.811-.05-.857-2.578.157-4.972 1.932-6.446 1.703-1.415 3.882-1.98 5.853-1.838-.576-3.583-4.196-6.348-8.596-6.348zM5.785 5.991c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178A1.17 1.17 0 0 1 4.623 7.17c0-.651.52-1.18 1.162-1.18zm5.813 0c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178 1.17 1.17 0 0 1-1.162-1.178c0-.651.52-1.18 1.162-1.18zm5.34 2.867c-1.797-.052-3.746.512-5.28 1.786-1.72 1.428-2.687 3.72-1.78 6.22.942 2.453 3.666 4.229 6.884 4.229.826 0 1.622-.12 2.361-.336a.722.722 0 0 1 .598.082l1.584.926a.272.272 0 0 0 .14.046c.133 0 .241-.11.241-.245 0-.06-.024-.12-.04-.178l-.325-1.233a.492.492 0 0 1 .177-.554C23.045 18.07 24 16.554 24 14.863c0-3.12-2.826-5.768-6.65-5.988v-.017h-.413zM14.6 13.2c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.97-.982zm4.844 0c.535 0 .969.44.969.982a.976.976 0 0 1-.97.983.976.976 0 0 1-.968-.983c0-.542.434-.982.969-.982z" fill="#07C160"/></svg>"##
            }
            Self::Apple => {
                r##"<svg viewBox="0 0 24 24" width="20" height="20"><path d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" fill="#000"/></svg>"##
            }
            Self::Microsoft => {
                r##"<svg viewBox="0 0 24 24" width="20" height="20"><rect x="1" y="1" width="10" height="10" fill="#F25022"/><rect x="13" y="1" width="10" height="10" fill="#7FBA00"/><rect x="1" y="13" width="10" height="10" fill="#00A4EF"/><rect x="13" y="13" width="10" height="10" fill="#FFB900"/></svg>"##
            }
            Self::Qq => {
                r##"<svg viewBox="0 0 24 24" width="20" height="20"><path d="M12 2C7.589 2 4 5.589 4 9.996c0 1.528.432 2.954 1.174 4.168-.368 1.276-1.04 3.072-1.822 4.448-.164.288.068.618.342.492 1.744-.8 3.356-1.902 4.388-2.668A7.96 7.96 0 0 0 12 17c1.386 0 2.682-.354 3.822-.978 1.032.766 2.644 1.868 4.388 2.668.274.126.506-.204.342-.492-.782-1.376-1.454-3.172-1.822-4.448A7.932 7.932 0 0 0 20 9.996C20 5.589 16.411 2 12 2zm-2.4 11a1.2 1.2 0 1 1 0-2.4 1.2 1.2 0 0 1 0 2.4zm4.8 0a1.2 1.2 0 1 1 0-2.4 1.2 1.2 0 0 1 0 2.4z" fill="#12B7F5"/></svg>"##
            }
        }
    }
}

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
    pub display_name: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub client_id: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub client_secret: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub authorize_url: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub token_url: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub userinfo_url: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub scopes: FieldUpdate<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<bool>)]
    pub enabled: FieldUpdate<bool>,
}

impl Validate for UpdateSocialProviderRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        self.display_name
            .reject_clear("display_name", &mut errors, |v| {
                validation::validate_length(v, 1, 64)
            });
        self.client_id
            .reject_clear("client_id", &mut errors, |v| {
                validation::validate_length(v, 1, 255)
            });
        self.client_secret
            .reject_clear("client_secret", &mut errors, |v| {
                validation::validate_length(v, 1, 4096)
            });
        self.authorize_url
            .reject_clear("authorize_url", &mut errors, |v| {
                validation::validate_url(v)
            });
        self.token_url
            .reject_clear("token_url", &mut errors, |v| validation::validate_url(v));
        self.userinfo_url
            .reject_clear("userinfo_url", &mut errors, |v| validation::validate_url(v));
        self.scopes.reject_clear("scopes", &mut errors, |v| {
            validation::validate_non_empty_items(v)
        });
        self.enabled
            .reject_clear("enabled", &mut errors, |_| Ok(()));
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
    pub email_verified: bool,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

impl SocialUserInfo {
    pub fn is_trusted_provider(&self) -> bool {
        matches!(self.provider.as_str(), "google" | "github" | "microsoft" | "apple")
    }
}
