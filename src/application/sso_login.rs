use crate::application::identity::register as register_use_case;
use crate::domain::auth::service::AuthService;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::sso::models::{LoginForm, RegisterForm, SsoSession};
use crate::domain::sso::repo::SsoSessionStore;
use crate::domain::user::entity::User;
use crate::domain::user::repo::UserStore;
use crate::shared::error::AppError;

pub async fn login_and_authenticate(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    sso_sessions: &dyn SsoSessionStore,
    session_id: &str,
    sso: &mut SsoSession,
    form: &LoginForm,
    ttl_seconds: i64,
) -> Result<User, AppError> {
    let user = AuthService::authenticate_with_password(
        users,
        identities,
        &form.identifier_type,
        &form.identifier,
        &form.password,
    )
    .await?;
    mark_authenticated(sso_sessions, session_id, sso, user.id, ttl_seconds).await?;
    Ok(user)
}

pub async fn register_and_authenticate(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    sso_sessions: &dyn SsoSessionStore,
    session_id: &str,
    sso: &mut SsoSession,
    form: &RegisterForm,
    ttl_seconds: i64,
) -> Result<User, AppError> {
    let user = register_use_case::register_user_with_password(
        users,
        identities,
        &form.username,
        form.email.as_deref(),
        form.phone.as_deref(),
        form.nickname.as_deref(),
        &form.password,
    )
    .await?;
    mark_authenticated(sso_sessions, session_id, sso, user.id, ttl_seconds).await?;
    Ok(user)
}

pub async fn mark_authenticated(
    sso_sessions: &dyn SsoSessionStore,
    session_id: &str,
    sso: &mut SsoSession,
    user_id: uuid::Uuid,
    ttl_seconds: i64,
) -> Result<(), AppError> {
    sso.user_id = Some(user_id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    sso_sessions.update(session_id, sso, ttl_seconds).await
}
