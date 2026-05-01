use axum::http::HeaderMap;

use crate::shared::constants::cookies::ACCOUNT_TOKEN;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub use crate::shared::utils::{extract_cookie, render_tpl};

pub async fn get_account_user_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, AppError> {
    let token = extract_cookie(headers, ACCOUNT_TOKEN).ok_or(AppError::Unauthorized)?;
    let claims = crate::infra::jwt::verify_token(&token, &state.jwt_keys)
        .map_err(|_| AppError::Unauthorized)?;
    claims.sub.parse().map_err(|_| AppError::Unauthorized)
}

pub async fn get_account_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::domain::identity::entity::User, AppError> {
    let user_id = get_account_user_id(state, headers).await?;
    crate::domain::identity::store::UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)
}

#[derive(Debug)]
pub struct UserView {
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub phone: String,
    pub phone_verified: bool,
    pub nickname: String,
    pub avatar_url: String,
    pub created_at: String,
}

impl UserView {
    pub fn from_user(user: &crate::domain::identity::entity::User) -> Self {
        Self {
            username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            phone: user.phone.clone().unwrap_or_default(),
            phone_verified: user.phone_verified,
            nickname: user.nickname.clone().unwrap_or_default(),
            avatar_url: user.avatar_url.clone().unwrap_or_default(),
            created_at: user.created_at.format("%Y-%m-%d %H:%M").to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SocialProviderView {
    pub key: String,
    pub icon: String,
    pub name: String,
    pub display_name: String,
    pub created_at: String,
    pub bound: bool,
    pub unbound: bool,
}

#[derive(Debug)]
pub struct ClientView {
    pub client_name: String,
    pub scopes: String,
    pub created_at: String,
}

#[derive(Debug)]
pub struct SessionView {
    pub session_id: String,
    pub device: String,
    pub location: String,
    pub created_at: String,
    pub current: bool,
    pub expired: bool,
}

pub fn user_initial(user: &crate::domain::identity::entity::User) -> String {
    if let Some(ref nick) = user.nickname {
        if !nick.is_empty() {
            return nick.chars().take(1).collect();
        }
    }
    user.username.chars().take(1).collect()
}

pub fn user_display_name(user: &crate::domain::identity::entity::User) -> String {
    if let Some(ref nick) = user.nickname {
        if !nick.is_empty() {
            return nick.clone();
        }
    }
    user.username.clone()
}
