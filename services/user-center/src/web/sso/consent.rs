use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::EntityTrait;

use crate::db::entity::{authorization_requests, oauth_clients, user_consents, users};
use crate::db::enums::UserStatus;
use crate::state::app::AppState;
use crate::state::session::SsoSession;
use crate::web::session::extract_session;
use crate::web::sso::template::{ConsentForm, ConsentTemplate};

/// 从 cookie 中解析 auth_request 并校验归属
///
/// 校验链：cookie 存在 → JSON 解析 → user_id 匹配 session → auth_request 存在且未完成且未过期
struct ConsentContext {
    auth_request: authorization_requests::Model,
}

async fn resolve_consent_context(
    state: &AppState,
    jar: &CookieJar,
    session: &SsoSession,
) -> Result<ConsentContext, Response> {
    let req_cookie = state.cookie_factory().auth_req_cookie_name();
    let raw = jar
        .get(&req_cookie)
        .map(|c| c.value().to_owned())
        .ok_or_else(|| Redirect::to("/sso/error?code=missing_request").into_response())?;

    let cookie_value = state
        .cookie_factory()
        .decode_auth_request(&raw)
        .map_err(|_| Redirect::to("/sso/error?code=invalid_request").into_response())?;

    // 校验 cookie 中的 user_id 与当前 session 匹配
    if cookie_value.user_id != session.user_id {
        return Err(Redirect::to("/sso/error?code=invalid_request").into_response());
    }

    let auth_request = authorization_requests::Entity::find_by_id(cookie_value.auth_request_id)
        .one(&state.db)
        .await
        .map_err(|_| Redirect::to("/sso/error?code=invalid_request").into_response())?
        .ok_or_else(|| Redirect::to("/sso/error?code=invalid_request").into_response())?;

    if auth_request.completed_at.is_some()
        || auth_request.expires_at < time::OffsetDateTime::now_utc()
    {
        return Err(Redirect::to("/sso/error?code=invalid_request").into_response());
    }

    if crate::service::oauth::requires_reauthentication(
        auth_request.prompt.as_deref(),
        auth_request.max_age,
        session.authenticated_at,
        session.created_at,
        auth_request.created_at,
        time::OffsetDateTime::now_utc(),
    ) {
        let response = match crate::web::oauth2::authorize::pending_redirect(
            state,
            jar,
            auth_request.id,
        )
        .await
        {
            Ok((jar, response)) => (jar, response).into_response(),
            Err(error) => error.into_response(),
        };
        return Err(response);
    }

    Ok(ConsentContext { auth_request })
}

/// EP-10: GET /sso/consent
///
/// 校验 session → 解析 cookie → 校验归属 → 查 client/user → 渲染授权确认页
pub async fn get(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Redirect::to("/sso/login").into_response(),
        Err(status) => return status.into_response(),
    };

    let ctx = match resolve_consent_context(&state, &jar, &session).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let client = match oauth_clients::Entity::find_by_id(ctx.auth_request.client_id)
        .one(&state.db)
        .await
    {
        Ok(Some(c)) => c,
        _ => return Redirect::to("/sso/error?code=invalid_client").into_response(),
    };

    let user = match users::Entity::find_by_id(session.user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) if u.status == UserStatus::Active => u,
        _ => return Redirect::to("/sso/login").into_response(),
    };

    let user_name = user
        .nickname
        .clone()
        .unwrap_or_else(|| user.username.clone());
    let user_email = user.email.clone().unwrap_or_default();
    let user_avatar_url = user.avatar_url.clone().unwrap_or_default();
    let user_initial = user_name
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    let client_display_name = client
        .name
        .clone()
        .unwrap_or_else(|| client.identifier.clone());

    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);

    let tpl = ConsentTemplate {
        csrf_token,
        client_name: client_display_name.clone(),
        client_url: client_display_name,
        scopes: ctx.auth_request.scopes,
        user_name,
        user_email,
        user_avatar_url,
        user_initial,
    };

    match tpl.render() {
        Ok(html) => (jar, axum::response::Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// EP-11: POST /sso/consent
///
/// action=deny → 标记完成 → redirect_uri?error=access_denied
/// action=allow → 事务：INSERT auth_code + UPSERT consent + UPDATE auth_request → redirect_uri?code=xxx
/// 其他 action → 拒绝
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ConsentForm>,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return Redirect::to("/sso/error?code=invalid_csrf").into_response();
    }

    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Redirect::to("/sso/login").into_response(),
        Err(status) => return status.into_response(),
    };

    let ctx = match resolve_consent_context(&state, &jar, &session).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let cookies = state.cookie_factory();
    let req_cookie = cookies.auth_req_cookie_name();

    if form.action == "deny" {
        if let Err(e) = crate::db::helper::auth_request::mark_completed(
            &state.db,
            ctx.auth_request.id,
            session.user_id,
        )
        .await
        {
            tracing::error!("Mark completed error: {e}");
        }
        let _ = user_consents::Entity::delete_by_id((session.user_id, ctx.auth_request.client_id))
            .exec(&state.db)
            .await;
        let jar = jar.add(cookies.clear_cookie(&req_cookie));
        let url = pero_utils::oauth::url::build_error_redirect_url(
            &ctx.auth_request.redirect_uri,
            "access_denied",
            None,
            ctx.auth_request.client_state.as_deref(),
        );
        return (jar, Redirect::to(&url)).into_response();
    }

    // 显式检查 action=allow，其他值拒绝
    if form.action != "allow" {
        return Redirect::to("/sso/error?code=invalid_action").into_response();
    }

    let oauth = state.oauth_service();
    let raw_code = match oauth
        .issue_auth_code_with_consent(ctx.auth_request.id, &session, true)
        .await
    {
        Ok(code) => code,
        Err(crate::service::oauth::OAuthError::Internal(e)) => {
            tracing::error!("Auth code issue error: {e}");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => {
            return Redirect::to("/sso/error?code=invalid_request").into_response();
        }
    };

    let jar = jar.add(cookies.clear_cookie(&req_cookie));
    let redirect = pero_utils::oauth::url::build_code_redirect_url(
        &ctx.auth_request.redirect_uri,
        &raw_code,
        ctx.auth_request.client_state.as_deref(),
    );
    (jar, Redirect::to(&redirect)).into_response()
}
