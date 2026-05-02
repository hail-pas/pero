use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::shared::patch::Patch;

use crate::domain::oauth2::entity::OAuth2Client;
use crate::shared::constants::oauth2::{self as oauth2_constants, scopes as oauth2_scopes};
use crate::shared::validation;

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
        match self {
            CodeChallengeMethod::S256 => "S256",
        }
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
    pub post_logout_redirect_uris: Vec<String>,
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
            post_logout_redirect_uris: c.post_logout_redirect_uris,
            enabled: c.enabled,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateClientResponse {
    pub client: OAuth2ClientDTO,
    pub client_secret: String,
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
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClientRequest {
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub client_name: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub redirect_uris: Patch<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub scopes: Patch<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub post_logout_redirect_uris: Patch<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<bool>)]
    pub enabled: Patch<bool>,
}

impl Validate for UpdateClientRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        self.client_name
            .validate_required("client_name", &mut errors, |v| {
                validation::validate_length(v, 1, 128)
            });
        self.redirect_uris
            .validate_required("redirect_uris", &mut errors, |v| {
                validation::validate_redirect_uris(v)
            });
        self.scopes.validate_required("scopes", &mut errors, |v| {
            if v.is_empty() {
                return Err(ValidationError::new("length"));
            }
            validation::validate_non_empty_items(v)?;
            Ok(())
        });
        self.post_logout_redirect_uris
            .validate("post_logout_redirect_uris", &mut errors, |v| {
                validation::validate_redirect_uris(v)
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
    pub login_hint: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    #[validate(length(max = 128))]
    pub code: Option<String>,
    #[validate(length(max = 2048))]
    pub redirect_uri: Option<String>,
    #[validate(length(max = 64))]
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

pub trait ClientCredentials {
    fn set_client_credentials(&mut self, client_id: String, client_secret: String);
}

impl ClientCredentials for TokenRequest {
    fn set_client_credentials(&mut self, client_id: String, client_secret: String) {
        self.client_id = Some(client_id);
        self.client_secret = Some(client_secret);
    }
}

impl ClientCredentials for RevokeRequest {
    fn set_client_credentials(&mut self, client_id: String, client_secret: String) {
        self.client_id = Some(client_id);
        self.client_secret = Some(client_secret);
    }
}
