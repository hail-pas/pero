use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_cache_redis::rate_limit_key::rl_reset_submit;
use pero_cache_redis::{RateLimitError, enforce_rate_limit};

use crate::service::account::{AccountService, PasswordResetError};
use crate::state::app::AppState;
use crate::web::sso::dto::{ResetPasswordForm, ResetPasswordView};

/// GET/POST /sso/reset-password 查询参数
#[derive(Debug, serde::Deserialize)]
pub struct ResetQuery {
    pub token: Option<String>,
}

/// EP-08: GET /sso/reset-password?token=xxx
///
/// 校验 token（签名 + purpose + 未过期） → 渲染重置密码页
pub async fn get_reset(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ResetQuery>,
) -> Response {
    let token = match query.token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return render_reset(
                jar,
                &state,
                String::new(),
                "missing_token".to_owned(),
                String::new(),
            );
        }
    };

    match AccountService::new(&state)
        .inspect_password_reset_token(&token)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return render_reset(
                jar,
                &state,
                token,
                "token_already_used".to_owned(),
                String::new(),
            );
        }
        Err(e) => {
            return render_reset_error(jar, &state, token, e);
        }
    }

    render_reset(jar, &state, token, String::new(), String::new())
}

/// EP-09: POST /sso/reset-password?token=xxx
///
/// 流程：校验 token/限流 → 调用 service 完成重置事务与登录态撤销。
pub async fn post_reset(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ResetQuery>,
    axum::Form(form): axum::Form<ResetPasswordForm>,
) -> Response {
    let token = match query.token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return render_reset(
                jar,
                &state,
                String::new(),
                "missing_token".to_owned(),
                String::new(),
            );
        }
    };

    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return render_reset(jar, &state, token, "invalid_csrf".to_owned(), String::new());
    }

    let account_svc = AccountService::new(&state);
    let user_id = match account_svc.verify_password_reset_token(&token) {
        Ok(id) => id,
        Err(e) => {
            return render_reset_error(jar, &state, token, e);
        }
    };

    let Ok(key) = rl_reset_submit.key(&user_id.to_string()) else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match enforce_rate_limit(&state.cache, &key, 5).await {
        Ok(()) => {}
        Err(RateLimitError::Denied { .. }) => {
            return render_reset(jar, &state, token, "rate_limited".to_owned(), String::new());
        }
        Err(RateLimitError::Redis(e)) => {
            tracing::error!(error = %e, "rate_limit_check redis error");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    match account_svc
        .reset_password(&token, &form.new_password, &form.confirm_password)
        .await
    {
        Ok(()) => render_reset(
            jar,
            &state,
            token,
            String::new(),
            "password_reset_success".to_owned(),
        ),
        Err(e) => render_reset_error(jar, &state, token, e),
    }
}

fn render_reset_error(
    jar: CookieJar,
    state: &AppState,
    token: String,
    error: PasswordResetError,
) -> Response {
    match error {
        PasswordResetError::Internal => {
            crate::web::util::dependency_error("Password reset dependency unavailable")
        }
        error => render_reset(
            jar,
            state,
            token,
            error.message_key().to_owned(),
            String::new(),
        ),
    }
}

fn render_reset(
    jar: CookieJar,
    state: &AppState,
    token: String,
    error: String,
    success: String,
) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "ResetPasswordView", |csrf_token| ResetPasswordView {
            token,
            error,
            success,
            csrf_token,
        })
}
