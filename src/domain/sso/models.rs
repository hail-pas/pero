use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub authorize_params: AuthorizeParams,
    pub user_id: Option<uuid::Uuid>,
    pub authenticated: bool,
    #[serde(default)]
    pub auth_time: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginForm {
    #[validate(length(min = 1, max = 255))]
    pub identifier: String,
    #[serde(default)]
    pub identifier_type: crate::domain::identity::models::IdentifierType,
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterForm {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(email)]
    pub email: Option<String>,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(
        length(max = 20),
        custom(function = "crate::shared::validation::validate_phone")
    )]
    pub phone: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(length(min = 1, max = 64))]
    pub nickname: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordForm {
    #[validate(
        length(min = 3, max = 255),
        custom(function = "crate::shared::validation::validate_email_or_phone")
    )]
    pub identifier: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordForm {
    #[validate(length(min = 8, max = 128))]
    pub old_password: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConsentDecision {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
pub struct ConsentAction {
    pub action: ConsentDecision,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordForm {
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
    #[validate(length(min = 8, max = 128))]
    pub confirm_password: String,
}
