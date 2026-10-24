use axum::http::StatusCode;
use axum_extra::extract::cookie::CookieJar;

use crate::state::app::AppState;
use crate::state::session::SsoSession;

pub async fn extract_session(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<SsoSession>, StatusCode> {
    let Some(cookie) = jar.get(&state.config.sso.session_cookie_name) else {
        return Ok(None);
    };
    state
        .session_service()
        .validate(cookie.value())
        .await
        .map_err(|error| {
            tracing::error!(%error, "Session validation unavailable");
            StatusCode::SERVICE_UNAVAILABLE
        })
}

/// Browser credential lookup for MFA/recovery and logout only. This does not
/// establish an authenticated session for application or protocol access.
pub(crate) async fn extract_browser_session(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<crate::db::entity::sso_sessions::Model>, StatusCode> {
    use crate::db::{
        entity::{sso_sessions, users},
        enums::UserStatus,
        helper::session::valid_query,
    };
    use sea_orm::{ColumnTrait, QueryFilter};
    let Some(cookie) = jar.get(&state.config.sso.session_cookie_name) else {
        return Ok(None);
    };
    let row = valid_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
    )
    .filter(sso_sessions::Column::TokenHash.eq(pero_utils::crypto::sha256_hex(cookie.value())))
    .find_also_related(users::Entity)
    .one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error=%e,"Browser session lookup unavailable");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    Ok(row.and_then(|(s, u)| {
        u.filter(|u| u.deleted_at.is_none() && u.status == UserStatus::Active)
            .map(|_| s)
    }))
}
