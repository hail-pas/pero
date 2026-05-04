use crate::application::auth::session_issuer;
use crate::domain::auth::repo::SessionStore;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::credential::service::hash_password;
use crate::domain::oauth::repo::TokenSigner;
use crate::domain::user::models::{
    CreateUserRequest, RegisterRequest, TokenResponse, User, UserDTO,
};
use crate::domain::user::repo::UserStore;
use crate::shared::error::AppError;

pub async fn register_user(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    sessions_store: &dyn SessionStore,
    signer: &dyn TokenSigner,
    req: &RegisterRequest,
    device: &str,
    location: &str,
    access_ttl_minutes: i64,
    refresh_ttl_days: i64,
) -> Result<TokenResponse, AppError> {
    let user = register_user_with_password(
        users,
        identities,
        &req.username,
        req.email.as_deref(),
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &req.password,
    )
    .await?;

    session_issuer::issue_tokens(
        signer,
        sessions_store,
        &user,
        access_ttl_minutes,
        refresh_ttl_days,
        device,
        location,
    )
    .await
}

pub async fn create_user(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    req: &CreateUserRequest,
) -> Result<UserDTO, AppError> {
    let user = register_user_with_password(
        users,
        identities,
        &req.username,
        req.email.as_deref(),
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &req.password,
    )
    .await?;
    Ok(user.into())
}

pub async fn register_user_with_password(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    username: &str,
    email: Option<&str>,
    phone: Option<&str>,
    nickname: Option<&str>,
    password: &str,
) -> Result<User, AppError> {
    let password_hash = hash_password(password)?;
    users
        .check_new_user_conflicts(username, email, phone)
        .await?;
    let user = users.create_user(username, email, phone, nickname).await?;
    identities.create_password(user.id, &password_hash).await?;
    Ok(user)
}
