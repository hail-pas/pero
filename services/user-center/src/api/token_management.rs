use crate::{
    db::entity::{apps, oauth_clients, refresh_tokens, sso_sessions, user_app_access},
    service::token_status,
    state::app::AppState,
};
use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, TransactionTrait};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    token: String,
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
    token_type_hint: Option<String>,
}
fn json(value: serde_json::Value) -> Response {
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::PRAGMA, "no-cache"),
        ],
        axum::Json(value),
    )
        .into_response()
}
async fn refresh(
    state: &AppState,
    token: &str,
    client: &oauth_clients::Model,
) -> Result<Option<refresh_tokens::Model>, sea_orm::DbErr> {
    refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::TokenHash.eq(pero_utils::crypto::sha256_hex(token)))
        .filter(refresh_tokens::Column::ClientId.eq(client.id))
        .one(&state.db)
        .await
}
pub async fn introspect(
    State(state): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: axum::http::HeaderMap,
    Form(mut input): Form<Input>,
) -> Response {
    let client = match super::client_auth::authenticate(
        &state,
        &headers,
        &mut input.client_id,
        &mut input.client_secret,
        &source.for_rate_limit(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return e,
    };
    // Public clients cannot inspect tokens: possession of client_id is not authentication.
    if client.r#type != crate::db::enums::OauthClientType::Confidential {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    match inspect(&state, &input.token, &client).await {
        Ok(v) => json(v),
        Err(e) => crate::web::util::dependency_error(e),
    }
}
async fn inspect(
    state: &AppState,
    token: &str,
    client: &oauth_clients::Model,
) -> Result<serde_json::Value, sea_orm::DbErr> {
    if let Some((claims, _, owner)) = token_status::active_access(state, token).await?
        && owner.id == client.id
    {
        return Ok(serde_json::json!({
            "active":true,"client_id":client.identifier,"sub":claims.sub,"scope":claims.scope,
            "exp":claims.exp,"iat":claims.iat,"iss":claims.iss,"aud":claims.aud,"sid":claims.sid,"token_type":"Bearer"
        }));
    }
    let Some(rt) = refresh(state, token, client).await? else {
        return Ok(serde_json::json!({"active":false}));
    };
    let now = time::OffsetDateTime::now_utc();
    if rt.revoked_at.is_some()
        || rt.expires_at <= now
        || !crate::service::scope::allowed(&rt.scopes, &client.scopes)
        || crate::service::access::active_app_access(&state.db, rt.user_id, client.app_id)
            .await?
            .is_none()
    {
        return Ok(serde_json::json!({"active":false}));
    }
    let session =
        crate::db::helper::session::active_query(now, state.config.sso.session_idle_ttl_seconds)
            .filter(sso_sessions::Column::Id.eq(rt.session_id))
            .filter(sso_sessions::Column::UserId.eq(rt.user_id))
            .one(&state.db)
            .await?;
    let user = crate::db::entity::users::Entity::find_by_id(rt.user_id)
        .one(&state.db)
        .await?;
    if session.is_none()
        || !user.is_some_and(|u| {
            u.deleted_at.is_none() && u.status == crate::db::enums::UserStatus::Active
        })
    {
        return Ok(serde_json::json!({"active":false}));
    }
    Ok(
        serde_json::json!({"active":true,"client_id":client.identifier,"sub":rt.user_id,"scope":rt.scopes.join(" "),"exp":rt.expires_at.unix_timestamp(),"iat":rt.created_at.unix_timestamp()}),
    )
}
pub async fn revoke(
    State(state): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: axum::http::HeaderMap,
    Form(mut input): Form<Input>,
) -> Response {
    let client = match super::client_auth::authenticate(
        &state,
        &headers,
        &mut input.client_id,
        &mut input.client_secret,
        &source.for_rate_limit(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return e,
    };
    let _ = &input.token_type_hint; // A hint never prevents trying both supported token types.
    let result = async {
        let user = if let Some(rt) = refresh(&state, &input.token, &client).await? {
            if rt.expires_at <= time::OffsetDateTime::now_utc()
                || rt.revoked_at.is_some() && rt.revoke_reason.as_deref() != Some("rotation")
            {
                None
            } else {
                Some(rt.user_id)
            }
        } else {
            token_status::active_access(&state, &input.token)
                .await?
                .filter(|(_, _, c)| c.id == client.id)
                .map(|(_, u, _)| u.id)
        };
        if let Some(user) = user {
            let txn = state.db.begin().await?;
            // Match issuance's client -> app -> access -> user lock order.
            oauth_clients::Entity::find_by_id(client.id)
                .lock_shared()
                .one(&txn)
                .await?;
            apps::Entity::find_by_id(client.app_id)
                .lock_shared()
                .one(&txn)
                .await?;
            user_app_access::Entity::find_by_id((user, client.app_id))
                .lock_exclusive()
                .one(&txn)
                .await?;
            crate::service::session::SessionService::revoke_app_grants(
                &txn,
                client.app_id,
                Some(user),
                "token_revoked",
            )
            .await?;
            txn.commit().await?;
        }
        Ok::<_, sea_orm::DbErr>(())
    }
    .await;
    match result {
        Ok(()) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            axum::http::StatusCode::OK,
        )
            .into_response(),
        Err(e) => crate::web::util::dependency_error(e),
    }
}
