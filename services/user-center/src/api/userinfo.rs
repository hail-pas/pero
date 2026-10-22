use axum::extract::State;
use axum::response::{IntoResponse, Response};
use pero_api_axum::oauth::bearer_error_response;
use pero_error::protocol::oauth::BearerError;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::db::enums::UserStatus;
use crate::state::app::AppState;

/// GET /api/oauth2/userinfo
pub async fn userinfo(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => return bearer_error_response(BearerError::invalid_token("Missing Bearer token")),
    };

    let kid = match pero_utils::oauth::jwt::decode_jwt_kid(token) {
        Ok(k) => k,
        Err(_) => {
            return bearer_error_response(BearerError::invalid_token("Missing or invalid kid"));
        }
    };

    let key =
        match crate::db::helper::signing_key::find_verification_key_by_kid(&state.db, &kid).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return bearer_error_response(BearerError::invalid_token("Unknown signing key"));
            }
            Err(e) => {
                tracing::error!("Signing key lookup: {e}");
                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        };

    let unverified_claims =
        match pero_utils::oauth::jwt::decode_access_token_claims_unverified(token) {
            Ok(c) => c,
            Err(_) => {
                return bearer_error_response(BearerError::invalid_token(
                    "Token claims decode failed",
                ));
            }
        };

    if unverified_claims.aud.trim().is_empty() {
        return bearer_error_response(BearerError::invalid_token("Missing audience"));
    }

    let client = match crate::db::entity::oauth_clients::Entity::find()
        .filter(crate::db::entity::oauth_clients::Column::Identifier.eq(&unverified_claims.aud))
        .one(&state.db)
        .await
    {
        Ok(Some(c)) if c.status == crate::db::enums::CommonStatus::Active => c,
        Ok(_) => return bearer_error_response(BearerError::invalid_token("Client is not active")),
        Err(e) => {
            tracing::error!("UserInfo client lookup: {e}");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let claims = match pero_utils::oauth::jwt::verify_access_token(
        token,
        &state.config.oidc.issuer,
        &client.identifier,
        &key.public_key_pem,
    ) {
        Ok(c) => c,
        Err(_) => {
            return bearer_error_response(BearerError::invalid_token("Token verification failed"));
        }
    };

    let user_id = match uuid::Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return bearer_error_response(BearerError::invalid_token("Invalid subject")),
    };

    let user = match crate::db::entity::users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return bearer_error_response(BearerError::invalid_token("User not found")),
        Err(e) => {
            tracing::error!("UserInfo user lookup: {e}");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    if user.deleted_at.is_some() || user.status != UserStatus::Active {
        return bearer_error_response(BearerError::invalid_token("User account is not active"));
    }

    match crate::service::access::can_user_access_active_app(&state.db, user.id, client.app_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return bearer_error_response(BearerError::invalid_token("Access revoked")),
        Err(e) => {
            tracing::error!("UserInfo access check: {e}");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    let Some(session_id) = claims
        .sid
        .as_deref()
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
    else {
        return bearer_error_response(BearerError::invalid_token("Session revoked"));
    };
    let session = crate::db::helper::session::active_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
    )
    .filter(crate::db::entity::sso_sessions::Column::Id.eq(session_id))
    .filter(crate::db::entity::sso_sessions::Column::UserId.eq(user.id))
    .one(&state.db)
    .await;
    match session {
        Ok(Some(_)) => {}
        Ok(None) => return bearer_error_response(BearerError::invalid_token("Session revoked")),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }

    let scopes: Vec<String> = claims.scope.split_whitespace().map(String::from).collect();
    if !crate::service::scope::contains(&scopes, "openid") {
        return bearer_error_response(BearerError::insufficient_scope("openid"));
    }
    if !crate::service::scope::allowed(&scopes, &client.scopes) {
        return bearer_error_response(BearerError::invalid_token("Scope revoked"));
    }
    let mut resp = serde_json::to_value(crate::service::scope::user_claims(&user, &scopes))
        .expect("user claims contain only JSON primitives");
    resp["sub"] = serde_json::json!(user.id.to_string());
    if crate::service::scope::contains(&scopes, "profile") {
        resp["updated_at"] = serde_json::json!(user.updated_at.unix_timestamp());
    }

    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::PRAGMA, "no-cache"),
        ],
        axum::Json(resp),
    )
        .into_response()
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
