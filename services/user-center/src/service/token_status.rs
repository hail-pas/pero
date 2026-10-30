//! One online access-token decision shared by UserInfo and introspection.
use crate::{
    db::{
        entity::{oauth_clients, sso_sessions, users},
        enums::{CommonStatus, UserStatus},
    },
    state::app::AppState,
};
use pero_utils::oauth::jwt::{self, AccessTokenClaims};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

pub async fn active_access(
    state: &AppState,
    token: &str,
) -> Result<Option<(AccessTokenClaims, users::Model, oauth_clients::Model)>, sea_orm::DbErr> {
    let Ok(kid) = jwt::decode_jwt_kid(token) else {
        return Ok(None);
    };
    let Some(key) =
        crate::db::helper::signing_key::find_verification_key_by_kid(&state.db, &kid).await?
    else {
        return Ok(None);
    };
    let Ok(unverified) = jwt::decode_access_token_claims_unverified(token) else {
        return Ok(None);
    };
    let Some(client) = oauth_clients::Entity::find()
        .filter(oauth_clients::Column::Identifier.eq(&unverified.aud))
        .filter(oauth_clients::Column::Status.eq(CommonStatus::Active))
        .one(&state.db)
        .await?
    else {
        return Ok(None);
    };
    let Ok(claims) = jwt::verify_access_token(
        token,
        &state.config.oidc.issuer,
        &client.identifier,
        &key.public_key_pem,
    ) else {
        return Ok(None);
    };
    let Ok(id) = uuid::Uuid::parse_str(&claims.sub) else {
        return Ok(None);
    };
    let Some(user) = users::Entity::find_by_id(id).one(&state.db).await? else {
        return Ok(None);
    };
    if user.deleted_at.is_some()
        || user.status != UserStatus::Active
        || claims.client_version != client.token_version
    {
        return Ok(None);
    }
    let Some(access) = super::access::active_app_access(&state.db, id, client.app_id).await? else {
        return Ok(None);
    };
    if access.token_version != claims.access_version {
        return Ok(None);
    }
    let Some(sid) = claims
        .sid
        .as_deref()
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
    else {
        return Ok(None);
    };
    if crate::db::helper::session::app_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
        client.app_id,
    )
    .filter(sso_sessions::Column::Id.eq(sid))
    .filter(sso_sessions::Column::UserId.eq(id))
    .one(&state.db)
    .await?
    .is_none()
    {
        return Ok(None);
    }
    let scopes = claims
        .scope
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<_>>();
    if !super::scope::allowed(&scopes, &client.scopes) {
        return Ok(None);
    }
    Ok(Some((claims, user, client)))
}
