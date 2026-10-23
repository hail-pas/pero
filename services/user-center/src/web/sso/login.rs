use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::extractor::ClientIp;

use crate::state::app::AppState;
use crate::web::login_flow::{LoginFormError, authenticate_password_form};
use crate::web::session::extract_session;
use crate::web::sso::dto::{LoginForm, LoginView, SocialProvider};
use crate::web::sso::utility::find_enabled_social_providers;

/// GET /sso/login 查询参数
#[derive(Debug, serde::Deserialize)]
pub struct LoginQuery {
    pub error: Option<String>,
}

/// EP-02: GET /sso/login
///
/// 已有 session → 读 pero_auth_nonce → 恢复授权 or /account/profile
/// 未登录 → 查询社交 provider → 渲染 login.html
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LoginQuery>,
) -> Response {
    let cookies = state.cookie_factory();
    if let Some(session) = match extract_session(&state, &jar).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    } {
        let nonce_name = cookies.nonce_cookie_name();
        if let Some(nonce_cookie) = jar.get(&nonce_name) {
            let nonce = nonce_cookie.value().to_owned();
            let oauth = state.oauth_service();
            match oauth.pending_request_requires_login(&nonce, &session).await {
                Ok(true) => {
                    let providers = match find_enabled_social_providers(&state).await {
                        Ok(providers) => providers,
                        Err(response) => return response,
                    };
                    return render_login(jar, &state, &providers, query.error.unwrap_or_default());
                }
                Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                Ok(false) => {}
            }
            match oauth.has_pending_request(&nonce).await {
                Ok(true) => return (jar, Redirect::to("/oauth2/authorize/resume")).into_response(),
                Ok(false) => {}
                Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
            let cleared = jar.add(cookies.clear_cookie(&nonce_name));
            return (cleared, Redirect::to("/account/profile")).into_response();
        }
        return (jar, Redirect::to("/account/profile")).into_response();
    }

    let providers = match find_enabled_social_providers(&state).await {
        Ok(providers) => providers,
        Err(response) => return response,
    };
    let error = query.error.unwrap_or_default();
    render_login(jar, &state, &providers, error)
}

/// EP-03: POST /sso/login
///
/// 完整流程：限流 → 查用户 → 检查锁定 → 查 password identity → 验证密码
/// → 创建 session → 记录事件 → 恢复 pending 授权 or /account/profile
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    let token = match authenticate_password_form(
        &state,
        &jar,
        ip,
        &form,
        crate::web::util::user_agent(&headers),
    )
    .await
    {
        Ok(token) => token,
        Err(LoginFormError::ServiceUnavailable) => {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(LoginFormError::Internal) => {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            let key = error.message_key().unwrap_or("invalid_credentials");
            return render_login_error_page(&state, jar, key).await;
        }
    };

    let cookies = state.cookie_factory();
    let nonce_name = cookies.nonce_cookie_name();
    let mut jar = jar;
    let redirect_target = if let Some(nonce_cookie) = jar.get(&nonce_name) {
        let nonce = nonce_cookie.value().to_owned();
        let oauth = state.oauth_service();
        match oauth.has_pending_request(&nonce).await {
            Ok(true) => "/oauth2/authorize/resume".to_owned(),
            Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
            Ok(false) => {
                jar = jar.add(cookies.clear_cookie(&nonce_name));
                "/account/profile".to_owned()
            }
        }
    } else {
        "/account/profile".to_owned()
    };

    let cookie = cookies.build_session_cookie(&token);
    (jar.add(cookie), Redirect::to(&redirect_target)).into_response()
}

fn render_login(
    jar: CookieJar,
    state: &AppState,
    providers: &[SocialProvider],
    error: String,
) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "LoginView", |csrf_token| LoginView {
            error,
            providers: providers.to_owned(),
            csrf_token,
        })
}

async fn render_login_error_page(state: &AppState, jar: CookieJar, error: &str) -> Response {
    let providers = match find_enabled_social_providers(state).await {
        Ok(providers) => providers,
        Err(response) => return response,
    };
    render_login(jar, state, &providers, error.to_owned())
}
