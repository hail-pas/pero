use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::shared::patch::FieldUpdate;

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
    #[validate(custom(function = "validate_grant_types"))]
    pub grant_types: Vec<String>,
    #[serde(default = "default_scopes")]
    #[validate(custom(function = "validate_allowed_scopes"))]
    pub scopes: Vec<String>,
    #[serde(default)]
    #[validate(custom(function = "crate::shared::validation::validate_redirect_uris"))]
    pub post_logout_redirect_uris: Vec<String>,
}

fn validate_grant_types(types: &[String]) -> Result<(), ValidationError> {
    if types.is_empty() {
        return Err(ValidationError::new("grant_types_required"));
    }

    if !types.iter().any(|v| v == oauth2_constants::GRANT_TYPE_AUTH_CODE) {
        return Err(ValidationError::new("authorization_code_required"));
    }

    let allowed = [
        oauth2_constants::GRANT_TYPE_AUTH_CODE,
        oauth2_constants::GRANT_TYPE_REFRESH_TOKEN,
    ];
    for gt in types {
        if !allowed.contains(&gt.as_str()) {
            let mut err = ValidationError::new("invalid_grant_type");
            err.message = Some(format!("'{}' is not a valid grant_type", gt).into());
            return Err(err);
        }
    }
    Ok(())
}

fn validate_allowed_scopes(scopes: &[String]) -> Result<(), ValidationError> {
    if scopes.is_empty() {
        return Err(ValidationError::new("length"));
    }
    let allowed = [
        oauth2_scopes::OPENID,
        oauth2_scopes::PROFILE,
        oauth2_scopes::EMAIL,
        oauth2_scopes::PHONE,
    ];
    for scope in scopes {
        if !allowed.contains(&scope.as_str()) {
            let mut err = ValidationError::new("invalid_scope");
            err.message = Some(format!("'{}' is not an allowed scope", scope).into());
            return Err(err);
        }
    }
    Ok(())
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
    pub client_name: FieldUpdate<String>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub redirect_uris: FieldUpdate<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub grant_types: FieldUpdate<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub scopes: FieldUpdate<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub post_logout_redirect_uris: FieldUpdate<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<bool>)]
    pub enabled: FieldUpdate<bool>,
}

impl Validate for UpdateClientRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        self.client_name
            .reject_clear("client_name", &mut errors, |v| {
                validation::validate_length(v, 1, 128)
            });
        self.redirect_uris
            .reject_clear("redirect_uris", &mut errors, |v| {
                validation::validate_redirect_uris(v)
            });
        self.grant_types
            .reject_clear("grant_types", &mut errors, |v| {
                if v.is_empty() {
                    return Err(ValidationError::new("length"));
                }
                validate_grant_types(v)
            });
        self.scopes.reject_clear("scopes", &mut errors, |v| {
            if v.is_empty() {
                return Err(ValidationError::new("length"));
            }
            validate_allowed_scopes(v)
        });
        self.post_logout_redirect_uris
            .validate("post_logout_redirect_uris", &mut errors, |v| {
                validation::validate_redirect_uris(v)
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
    #[validate(custom(function = "crate::shared::validation::validate_pkce_challenge"))]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: Option<String>,
    pub login_hint: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
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
    #[validate(
        length(min = 43, max = 128),
        custom(function = "crate::shared::validation::validate_pkce_verifier")
    )]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    fn has_client_id(&self) -> bool;
}

impl ClientCredentials for TokenRequest {
    fn set_client_credentials(&mut self, client_id: String, client_secret: String) {
        self.client_id = Some(client_id);
        self.client_secret = Some(client_secret);
    }

    fn has_client_id(&self) -> bool {
        self.client_id.is_some()
    }
}

impl ClientCredentials for RevokeRequest {
    fn set_client_credentials(&mut self, client_id: String, client_secret: String) {
        self.client_id = Some(client_id);
        self.client_secret = Some(client_secret);
    }

    fn has_client_id(&self) -> bool {
        self.client_id.is_some()
    }
}
