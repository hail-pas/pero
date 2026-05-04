use crate::domain::credential::repo::IdentityStore;
use crate::domain::federation::entity::SocialUserInfo;
use crate::domain::federation::http::HttpClient;
use crate::domain::federation::repo::SocialStore;
use crate::domain::federation::service::SocialState;
use crate::domain::user::entity::User;
use crate::domain::user::repo::UserStore;
use crate::shared::error::AppError;
use crate::shared::kv::KvStore;

pub async fn complete_social_login(
    social: &dyn SocialStore,
    identities: &dyn IdentityStore,
    users: &dyn UserStore,
    kv: &dyn KvStore,
    http: &dyn HttpClient,
    code: &str,
    state_token: &str,
    provider: &str,
    redirect_uri: &str,
) -> Result<(User, SocialUserInfo, SocialState), AppError> {
    let (user_info, social_state) = crate::domain::federation::service::handle_callback(
        social,
        kv,
        http,
        code,
        state_token,
        provider,
        redirect_uri,
    )
    .await?;
    let user =
        crate::domain::federation::service::find_or_create_user(users, identities, &user_info)
            .await?;
    Ok((user, user_info, social_state))
}

pub async fn complete_social_binding(
    social: &dyn SocialStore,
    identities: &dyn IdentityStore,
    kv: &dyn KvStore,
    http: &dyn HttpClient,
    user_id: uuid::Uuid,
    code: &str,
    state_token: &str,
    issuer: &str,
) -> Result<(), AppError> {
    crate::domain::federation::service::bind_social_identity(
        social,
        identities,
        kv,
        http,
        issuer,
        code,
        state_token,
        user_id,
    )
    .await
}
