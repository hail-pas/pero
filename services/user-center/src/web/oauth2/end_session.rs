use crate::{
    state::app::AppState,
    web::{
        session::extract_session,
        sso::template::{ConfirmLogoutTemplate, EndSessionTemplate},
    },
};
use askama::Template;
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;

#[derive(Debug, Default, serde::Deserialize)]
pub struct EndSessionQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub confirm: Option<String>,
    pub csrf_token: Option<String>,
    pub session_id: Option<String>,
}

// Reject repeated known parameters.
fn parse(input: &[u8]) -> Result<EndSessionQuery, StatusCode> {
    let mut fields = serde_json::Map::new();
    for (name, value) in url::form_urlencoded::parse(input) {
        if !matches!(
            name.as_ref(),
            "id_token_hint"
                | "post_logout_redirect_uri"
                | "state"
                | "confirm"
                | "csrf_token"
                | "session_id"
        ) {
            continue;
        }
        if fields
            .insert(name.into_owned(), value.into_owned().into())
            .is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    serde_json::from_value(fields.into()).map_err(|_| StatusCode::BAD_REQUEST)
}

pub async fn end_session(
    State(state): State<AppState>,
    jar: CookieJar,
    RawQuery(query): RawQuery,
) -> Response {
    match parse(query.as_deref().unwrap_or("").as_bytes()) {
        Ok(params) => handle(&state, jar, params, false).await,
        Err(status) => status.into_response(),
    }
}

pub async fn end_session_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';').next().is_some_and(|v| {
                v.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        })
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match parse(&body) {
        Ok(params) => handle(&state, jar, params, true).await,
        Err(status) => status.into_response(),
    }
}

async fn handle(
    state: &AppState,
    jar: CookieJar,
    query: EndSessionQuery,
    is_post: bool,
) -> Response {
    let session = match extract_session(state, &jar).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let plan = match crate::service::logout::prepare(
        state,
        query.id_token_hint.as_deref(),
        query.post_logout_redirect_uri.as_deref(),
        query.state.as_deref(),
        session.as_ref(),
    )
    .await
    {
        Ok(plan) => plan,
        Err(error) => {
            tracing::error!(%error, "Logout preparation failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let confirming = is_post && query.confirm.as_deref() == Some("yes");
    if confirming
        && (!state
            .web_security()
            .verify_csrf(&jar, query.csrf_token.as_deref().unwrap_or(""))
            || session
                .as_ref()
                .is_none_or(|s| query.session_id.as_deref() != Some(s.id.to_string().as_str())))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if plan.needs_confirmation && !confirming {
        return state
            .web_security()
            .render_with_csrf(jar, |csrf_token| ConfirmLogoutTemplate {
                csrf_token,
                session_id: session
                    .as_ref()
                    .expect("confirmation requires a session")
                    .id
                    .to_string(),
                id_token_hint: query.id_token_hint.unwrap_or_default(),
                post_logout_redirect_uri: query.post_logout_redirect_uri.unwrap_or_default(),
                state: query.state.unwrap_or_default(),
            });
    }
    if let Some(session) = session {
        if let Err(error) = state
            .session_service()
            .revoke_login_state(session.id, "logout")
            .await
        {
            tracing::error!(%error, "Session revoke failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let _ = crate::db::helper::login_event::record(
            &state.db,
            crate::db::helper::login_event::RecordParams {
                user_id: Some(session.user_id),
                identity_id: session.identity_id,
                provider_id: None,
                event_type: crate::db::enums::LoginEventType::Logout,
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
        .add(cookies.clear_cookie(&cookies.social_state_cookie_name()))
        .add(cookies.clear_cookie(security.csrf_cookie_name()));
    if let Some(target) = plan.redirect {
        return (jar, Redirect::to(&target)).into_response();
    }
    match EndSessionTemplate.render() {
        Ok(html) => (jar, axum::response::Html(html)).into_response(),
        Err(error) => {
            tracing::error!(%error, "Logout template failed");
            (jar, StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn form_parameters_reject_duplicates() {
        assert_eq!(
            parse(b"state=a%26b%2Bc").unwrap().state.as_deref(),
            Some("a&b+c")
        );
        assert!(parse(b"state=a&state=a").is_err());
        assert!(parse(b"id_token_hint=a&id_token_hint=b").is_err());
    }
}
