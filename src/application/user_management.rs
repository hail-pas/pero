use crate::domain::auth::repo::SessionStore;
use crate::domain::oauth::repo::OAuth2TokenStore;
use crate::domain::user::repo::UserStore;
use crate::shared::error::AppError;

pub async fn disable_user(
    users: &dyn UserStore,
    sessions: &dyn SessionStore,
    tokens: &dyn OAuth2TokenStore,
    user_id: uuid::Uuid,
) -> Result<(), AppError> {
    users.delete(user_id).await?;
    sessions.revoke_all_for_user(user_id).await?;
    tokens.revoke_all_for_user(user_id).await?;
    Ok(())
}
