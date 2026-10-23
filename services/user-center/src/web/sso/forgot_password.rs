use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_cache_redis::{RateLimitError, enforce_rate_limit};

use crate::state::app::AppState;
use crate::web::sso::dto::{ForgotPasswordForm, ForgotPasswordView};
use pero_cache_redis::rate_limit_key::{rl_reset, rl_reset_ip};

/// GET /sso/forgot-password 查询参数
#[derive(Debug, serde::Deserialize)]
pub struct ForgotQuery {
    pub error: Option<String>,
}

/// EP-06: GET /sso/forgot-password — 渲染忘记密码页
pub async fn get_forgot(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ForgotQuery>,
) -> Response {
    render_forgot(jar, &state, query.error.unwrap_or_default(), false)
}

/// EP-07: POST /sso/forgot-password
///
/// 流程：
/// 1. 限流
/// 2. 查找用户（email or phone）
/// 3. 签发 password reset JWT
/// 4. 事务内保存重置令牌和加密通知任务
/// 5. 返回成功页面（无论用户是否存在，防止信息泄露）
pub async fn post_forgot(
    State(state): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    jar: CookieJar,
    axum::Form(form): axum::Form<ForgotPasswordForm>,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return render_forgot(jar, &state, "invalid_csrf".to_owned(), false);
    }

    let identifier = form.identifier.trim();
    if identifier.is_empty() {
        return render_forgot(jar, &state, "identifier is required".to_owned(), false);
    }

    let Ok(source_key) = rl_reset_ip.key(&source.to_string()) else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match enforce_rate_limit(&state.cache, &source_key, 20).await {
        Ok(()) => {}
        Err(RateLimitError::Denied { .. }) => {
            return render_forgot(jar, &state, "rate_limited".to_owned(), false);
        }
        Err(RateLimitError::Redis(error)) => {
            tracing::error!(%error, "Recovery source rate limit unavailable");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    let rate_limit_key =
        pero_utils::crypto::sha256_hex(&pero_utils::string::canonical_rate_limit_key(identifier));
    let Ok(key) = rl_reset.key(&rate_limit_key) else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match enforce_rate_limit(&state.cache, &key, 3).await {
        Ok(()) => {}
        Err(RateLimitError::Denied { .. }) => {
            return render_forgot(jar, &state, "rate_limited".to_owned(), false);
        }
        Err(RateLimitError::Redis(e)) => {
            tracing::error!(error = %e, "rate_limit_check redis error");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    if let Err(error) = crate::service::recovery::request(&state, identifier).await {
        tracing::error!(%error, "Password recovery failed");
        return match error {
            crate::service::recovery::RecoveryError::Signing(_) => {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
        .into_response();
    }

    render_forgot(jar, &state, String::new(), true)
}

fn render_forgot(jar: CookieJar, state: &AppState, error: String, success: bool) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "ForgotPasswordView", |csrf_token| ForgotPasswordView {
            error,
            success,
            csrf_token,
        })
}
