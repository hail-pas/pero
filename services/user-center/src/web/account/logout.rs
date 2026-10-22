use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::db::enums::LoginEventType;
use crate::state::app::AppState;
use crate::web::session::extract_session;

#[derive(Debug, serde::Deserialize)]
pub struct LogoutForm {
    pub csrf_token: Option<String>,
}

/// EP-24: POST /account/logout
///
/// 撤销 session + refresh tokens → 清 cookie → 302 /oauth2/session/end
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<LogoutForm>,
) -> Response {
    if !state
        .web_security()
        .verify_csrf(&jar, form.csrf_token.as_deref().unwrap_or(""))
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "invalid_csrf"})),
        )
            .into_response();
    }
    if let Some(session) = match extract_session(&state, &jar).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    } {
        let session_svc = state.session_service();
        if let Err(e) = session_svc.revoke_login_state(session.id, "logout").await {
            tracing::error!("Logout revoke error: {e}");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }

        let _ = crate::db::helper::login_event::record(
            &state.db,
            crate::db::helper::login_event::RecordParams {
                user_id: Some(session.user_id),
                identity_id: session.identity_id,
                provider_id: None,
                event_type: LoginEventType::Logout,
                ip: None,
                user_agent: None,
                detail: serde_json::json!({}),
            },
        )
        .await;
    }

    let security = state.web_security();
    let cookies = security.cookies();
    let jar = jar
        .add(cookies.clear_cookie(cookies.session_cookie_name()))
        .add(cookies.clear_cookie(&cookies.auth_req_cookie_name()))
        .add(cookies.clear_cookie(&cookies.nonce_cookie_name()))
        .add(cookies.clear_cookie(security.csrf_cookie_name()));

    (jar, Redirect::to("/oauth2/session/end")).into_response()
}
