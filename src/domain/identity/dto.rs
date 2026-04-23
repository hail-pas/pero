use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::domain::identity::entity::User;
use crate::shared::patch::{Patch, validate_patch};
use crate::shared::validation;

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct UserDTO {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub status: i16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserDTO {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            phone: u.phone,
            nickname: u.nickname,
            avatar_url: u.avatar_url,
            email_verified: u.email_verified,
            status: u.status,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    #[validate(
        length(max = 20),
        custom(function = "crate::shared::validation::validate_phone")
    )]
    pub phone: Option<String>,
    #[validate(length(min = 1, max = 64))]
    pub nickname: Option<String>,
}

pub type CreateUserRequest = RegisterRequest;

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub phone: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub nickname: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub avatar_url: Patch<String>,
    #[serde(default)]
    pub status: Option<i16>,
}

impl Validate for UpdateUserRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Some(ref v) = self.username {
            if let Err(e) = validation::validate_length(v, 3, 64) {
                errors.add("username", e);
            }
        }
        if let Some(ref v) = self.email {
            if let Err(e) = validation::validate_email(v) {
                errors.add("email", e);
            }
        }
        validate_patch(
            &self.phone,
            "phone",
            |v| validation::validate_phone(v),
            &mut errors,
        );
        validate_patch(
            &self.nickname,
            "nickname",
            |v| validation::validate_length(v, 1, 64),
            &mut errors,
        );
        validate_patch(
            &self.avatar_url,
            "avatar_url",
            |v| validation::validate_url(v),
            &mut errors,
        );
        if let Some(v) = self.status {
            if !(0..=1).contains(&v) {
                errors.add("status", ValidationError::new("range"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMeRequest {
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub nickname: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub avatar_url: Patch<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub phone: Patch<String>,
}

impl Validate for UpdateMeRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_patch(
            &self.nickname,
            "nickname",
            |v| validation::validate_length(v, 1, 64),
            &mut errors,
        );
        validate_patch(
            &self.avatar_url,
            "avatar_url",
            |v| validation::validate_url(v),
            &mut errors,
        );
        validate_patch(
            &self.phone,
            "phone",
            |v| validation::validate_phone(v),
            &mut errors,
        );
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IdentifierType {
    #[default]
    Username,
    Email,
    Phone,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(length(min = 1, max = 255))]
    pub identifier: String,
    #[serde(default)]
    pub identifier_type: IdentifierType,
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserDTO,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RefreshRequest {
    #[validate(length(min = 1))]
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[allow(dead_code)]
pub struct BindRequest {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 8, max = 128))]
    pub old_password: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

impl ChangePasswordRequest {}
