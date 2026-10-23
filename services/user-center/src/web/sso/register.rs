use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use pero_api_axum::extractor::ClientIp;
use pero_cache_redis::RateLimitError;
use validator::Validate;

use crate::service::account::{AccountService, RegisterUserError, RegisterUserParams};
use crate::state::app::AppState;
use crate::web::sso::dto::{RegisterForm, RegisterView};
use crate::web::sso::utility::resolve_auth_request_id;

/// EP-04: GET /sso/register — 渲染注册页面
pub async fn get(State(state): State<AppState>, jar: CookieJar) -> Response {
    render_register(jar, &state, "")
}

/// EP-05: POST /sso/register
///
/// 完整流程：
/// 1. IP 限流
/// 2. 表单校验（username 3-64, password 8-128, email 格式）
/// 3. 密码策略校验
/// 4. username 唯一性检查
/// 5. email 唯一性检查（如有）
/// 6. phone 唯一性检查（如有）
/// 7. hash password
/// 8. 事务：INSERT users + INSERT identities
/// 9. 302 /sso/login?registered=1
pub async fn post(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    jar: CookieJar,
    axum::Form(mut form): axum::Form<RegisterForm>,
) -> Response {
    {
        use pero_cache_redis::enforce_rate_limit;
        use pero_cache_redis::rate_limit_key::rl_register_ip;

        let ip_str = ip.map(|v| v.to_string()).unwrap_or_else(|| {
            pero_config::blocks::ServerConfig::unknown_ip_placeholder().to_owned()
        });
        let Ok(key) = rl_register_ip.key(&ip_str) else {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        match enforce_rate_limit(&state.cache, &key, 5).await {
            Ok(()) => {}
            Err(RateLimitError::Denied { .. }) => {
                return render_register(jar, &state, "rate_limited");
            }
            Err(RateLimitError::Redis(e)) => {
                tracing::error!(error = %e, "rate_limit_check redis error");
                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    }

    let auth_request_id = match resolve_auth_request_id(&state, &jar).await {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(%error, "Pending authorization lookup failed");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return render_register(jar, &state, "invalid_csrf");
    }

    form.normalize_optional_fields();

    if let Err(errors) = Validate::validate(&form) {
        let msg = errors.to_string();
        return render_register(jar, &state, &msg);
    }

    if let Err(e) = AccountService::new(&state)
        .register_user(RegisterUserParams {
            username: form.username,
            email: form.email,
            phone: form.phone,
            nickname: form.nickname,
            password: form.password,
            auth_request_id,
        })
        .await
    {
        return match e {
            RegisterUserError::Internal => {
                crate::web::util::dependency_error("Registration failed")
            }
            error => render_register(jar, &state, error.message_key()),
        };
    }

    Redirect::to("/sso/login?registered=1").into_response()
}

fn render_register(jar: CookieJar, state: &AppState, error: &str) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "RegisterView", |csrf_token| RegisterView {
            error: error.to_owned(),
            csrf_token,
        })
}
