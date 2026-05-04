use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::credential::entity::Identity;
use crate::domain::user::dto as domain;

#[derive(Debug, Serialize, ToSchema)]
pub struct UserDTO {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub status: i16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<domain::UserDTO> for UserDTO {
    fn from(d: domain::UserDTO) -> Self {
        Self {
            id: d.id,
            username: d.username,
            email: d.email,
            phone: d.phone,
            nickname: d.nickname,
            avatar_url: d.avatar_url,
            email_verified: d.email_verified,
            phone_verified: d.phone_verified,
            status: d.status,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub phone: Option<String>,
    pub nickname: Option<String>,
}

impl From<RegisterRequest> for domain::RegisterRequest {
    fn from(r: RegisterRequest) -> Self {
        Self {
            username: r.username,
            email: r.email,
            password: r.password,
            phone: r.phone,
            nickname: r.nickname,
        }
    }
}

pub type CreateUserRequest = RegisterRequest;

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserDTO,
}

impl From<domain::TokenResponse> for TokenResponse {
    fn from(d: domain::TokenResponse) -> Self {
        Self {
            access_token: d.access_token,
            refresh_token: d.refresh_token,
            user: d.user.into(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl From<domain::RefreshTokenResponse> for RefreshTokenResponse {
    fn from(d: domain::RefreshTokenResponse) -> Self {
        Self {
            access_token: d.access_token,
            refresh_token: d.refresh_token,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub identifier: String,
    pub identifier_type: Option<String>,
    pub password: String,
}

impl From<LoginRequest> for domain::LoginRequest {
    fn from(r: LoginRequest) -> Self {
        let identifier_type = match r.identifier_type.as_deref() {
            Some("email") => domain::IdentifierType::Email,
            Some("phone") => domain::IdentifierType::Phone,
            _ => domain::IdentifierType::default(),
        };
        Self {
            identifier: r.identifier,
            identifier_type,
            password: r.password,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl From<RefreshRequest> for domain::RefreshRequest {
    fn from(r: RefreshRequest) -> Self {
        Self {
            refresh_token: r.refresh_token,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

impl From<ChangePasswordRequest> for domain::ChangePasswordRequest {
    fn from(r: ChangePasswordRequest) -> Self {
        Self {
            old_password: r.old_password,
            new_password: r.new_password,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityDTO {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_uid: String,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Identity> for IdentityDTO {
    fn from(d: Identity) -> Self {
        Self {
            id: d.id,
            user_id: d.user_id,
            provider: d.provider,
            provider_uid: d.provider_uid,
            verified: d.verified,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserAttributeDTO {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key: String,
    pub value: String,
}

impl From<domain::UserAttribute> for UserAttributeDTO {
    fn from(d: domain::UserAttribute) -> Self {
        Self {
            id: d.id,
            user_id: d.user_id,
            key: d.key,
            value: d.value,
        }
    }
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct UpdateMeRequest {
    pub email: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
}

impl From<UpdateMeRequest> for domain::UpdateMeRequest {
    fn from(r: UpdateMeRequest) -> Self {
        use crate::shared::patch::FieldUpdate;
        Self {
            email: r
                .email
                .map(FieldUpdate::Set)
                .unwrap_or(FieldUpdate::Unchanged),
            nickname: r
                .nickname
                .map(FieldUpdate::Set)
                .unwrap_or(FieldUpdate::Unchanged),
            avatar_url: r
                .avatar_url
                .map(FieldUpdate::Set)
                .unwrap_or(FieldUpdate::Unchanged),
            phone: r
                .phone
                .map(FieldUpdate::Set)
                .unwrap_or(FieldUpdate::Unchanged),
        }
    }
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub status: Option<i16>,
}
