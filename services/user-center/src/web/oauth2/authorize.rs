use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::db::entity::authorization_requests;
use crate::db::entity::users;
use crate::db::enums::{CodeChallengeMethod, OauthClientType, UserStatus};
use crate::service::oauth::CreateAuthorizationRequestParams;
use crate::state::app::AppState;
use crate::web::error::OAuthError;
use crate::web::security::AuthReqCookieValue;
use crate::web::session::extract_session;
use sea_orm::EntityTrait;

/// GET /oauth2/authorize 查询参数
///
/// - `client_id` / `redirect_uri`: 必填，用 validator 校验非空
/// - `response_type` / `scope`: 不走 validator，在 redirect_uri 白名单校验后做 OAuth 校验
///   以便只向已验证的 redirect_uri 返回 `unsupported_response_type` / `invalid_scope`
/// - `code_challenge_method`: 可选，有值时校验 ascii 长度，业务校验（必须 S256）在
///   redirect_uri 白名单校验后进行
/// - `prompt` / `login_hint` / `nonce` 等: 纯透传，无格式约束
#[derive(Debug, Default, validator::Validate, serde::Deserialize)]
#[serde(default)]
pub struct AuthorizeQuery {
    #[validate(length(min = 1))]
    pub client_id: String,
    #[validate(length(min = 1))]
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    #[validate(length(min = 1, max = 10))]
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
}

impl AuthorizeQuery {
    /// 仅做不会触发 OAuth redirect 的结构校验。
    ///
    /// OAuth2 安全要求：只有在 `client_id` 存在且 `redirect_uri` 已通过客户端白名单校验后，
    /// 才能把错误重定向回客户端。因此这里不能返回 `RedirectError`。
    pub fn validate_oauth(&self) -> Result<(), OAuthError> {
        if let Err(errors) = validator::Validate::validate(self) {
            return Err(report_into_oauth_error(errors, self));
        }

        Ok(())
    }

    /// redirect_uri 已经通过客户端白名单校验后的 OAuth 参数校验。
    ///
    /// 这些错误可安全地按 OAuth2 规范重定向给客户端：
    /// - response_type 缺失/不支持
    /// - scope 缺失
    /// - PKCE challenge method 不支持
    pub fn validate_redirectable_oauth(&self) -> Result<(), OAuthError> {
        if self.max_age.is_some_and(|age| age < 0) {
            return Err(self.redirect_err("invalid_request", Some("max_age must be nonnegative")));
        }
        if let Some(prompt) = &self.prompt {
            let values: Vec<_> = prompt.split_whitespace().collect();
            if values.contains(&"select_account") {
                return Err(self.redirect_err(
                    "invalid_request",
                    Some("prompt=select_account is not supported"),
                ));
            }
            if values.is_empty()
                || values
                    .iter()
                    .any(|p| !matches!(*p, "none" | "login" | "consent" | "select_account"))
                || (values.contains(&"none") && values.len() != 1)
            {
                return Err(self.redirect_err("invalid_request", Some("Invalid prompt")));
            }
        }
        if self.response_type.trim().is_empty() {
            return Err(self.redirect_err("invalid_request", Some("response_type is required")));
        }
        if self.response_type != "code" {
            return Err(self.redirect_err("unsupported_response_type", None));
        }

        if self.scope.trim().is_empty() {
            return Err(self.redirect_err("invalid_scope", None));
        }

        if let Some(method) = &self.code_challenge_method {
            if method != "S256" {
                return Err(self.redirect_err(
                    "invalid_request",
                    Some("Only S256 code_challenge_method is supported"),
                ));
            }
        } else if self.code_challenge.is_some() {
            // RFC 7636 §4.3: code_challenge_method 在有 code_challenge 时必须提供
            return Err(self.redirect_err(
                "invalid_request",
                Some("code_challenge_method is required when code_challenge is provided"),
            ));
        }

        Ok(())
    }

    pub fn scopes(&self) -> Vec<String> {
        self.scope.split_whitespace().map(String::from).collect()
    }

    pub fn redirect_err(&self, error: &str, desc: Option<&str>) -> OAuthError {
        OAuthError::redirect(&self.redirect_uri, error, desc, self.state.as_deref())
    }

    /// 将 code_challenge_method 字符串映射为枚举（只接受 S256/plain）
    pub fn challenge_method(&self) -> Option<CodeChallengeMethod> {
        self.code_challenge_method.as_deref().and_then(|m| match m {
            "S256" => Some(CodeChallengeMethod::S256),
            _ => None,
        })
    }
}

/// EP-01: GET /oauth2/authorize
///
/// OAuth2 授权入口，完整流程：
/// 1. 参数校验（validate_oauth）
/// 2. 验证 client/app 合法性（DB.R）
/// 3. public client 必须携带 PKCE
/// 4. prompt=none 快速失败路径：无 session → login_required，用户非 active → login_required，无 consent → consent_required
/// 5. 创建 authorization_request（DB.W）
/// 6. prompt=login → 存 pending request（Redis）+ 设 nonce cookie → 302 /sso/login
/// 7. 进入 resolve_authorization 共享决策逻辑
pub async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<AuthorizeQuery>,
) -> Result<(CookieJar, Response), OAuthError> {
    params.validate_oauth()?;

    let scopes = params.scopes();

    let oauth = state.oauth_service();
    let client = oauth
        .validate_client(&params.client_id, &params.redirect_uri, &[])
        .await?;

    params.validate_redirectable_oauth()?;

    if !crate::service::scope::allowed(&scopes, &client.scopes) {
        return Err(params.redirect_err("invalid_scope", None));
    }

    if client.r#type == OauthClientType::Public && params.code_challenge.is_none() {
        return Err(params.redirect_err(
            "invalid_request",
            Some("PKCE is required for public clients"),
        ));
    }

    let app = oauth.validate_app(&client).await?;

    // prompt=none: 不允许展示任何 UI，所有缺失条件直接以 error code 返回
    // 通过所有检查后立即生成 code 并 302，不走 resolve_authorization 避免重复查询
    if crate::service::oauth::has_prompt(params.prompt.as_deref(), "none") {
        let Some(session) = extract_session(&state, &jar)
            .await
            .map_err(|_| OAuthError::Unavailable)?
        else {
            return Err(params.redirect_err("login_required", None));
        };

        if crate::service::oauth::requires_reauthentication(
            params.prompt.as_deref(),
            params.max_age,
            session.authenticated_at,
            session.created_at,
            time::OffsetDateTime::now_utc(),
            time::OffsetDateTime::now_utc(),
        ) {
            return Err(params.redirect_err("login_required", None));
        }

        // 检查用户状态
        let user = users::Entity::find_by_id(session.user_id)
            .one(&state.db)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;
        if user
            .as_ref()
            .is_some_and(|u| u.status != UserStatus::Active)
            || user.is_none()
        {
            return Err(params.redirect_err("login_required", None));
        }

        if !oauth.check_app_access(session.user_id, app.id).await? {
            return Err(params.redirect_err(
                "access_denied",
                Some("User does not have access to this application"),
            ));
        }
        if !oauth
            .check_consent(session.user_id, client.id, &scopes)
            .await?
        {
            return Err(params.redirect_err("consent_required", None));
        }

        // 所有检查通过：创建 auth_request → 生成 code → 302
        let auth_request = oauth
            .create_authorization_request(CreateAuthorizationRequestParams {
                client_id: client.id,
                app_id: app.id,
                redirect_uri: params.redirect_uri.clone(),
                scopes,
                client_state: params.state.clone(),
                nonce: params.nonce.clone(),
                code_challenge: params.code_challenge.clone(),
                code_challenge_method: params.challenge_method(),
                prompt: params.prompt.clone(),
                max_age: params.max_age,
                login_hint: params.login_hint.clone(),
            })
            .await?;

        let code = oauth
            .issue_auth_code_with_consent(auth_request.id, &session, false)
            .await?;
        let redirect = pero_utils::oauth::url::build_code_redirect_url(
            &params.redirect_uri,
            &code,
            params.state.as_deref(),
        );
        return Ok((jar, Redirect::to(&redirect).into_response()));
    }

    let auth_request = oauth
        .create_authorization_request(CreateAuthorizationRequestParams {
            client_id: client.id,
            app_id: app.id,
            redirect_uri: params.redirect_uri.clone(),
            scopes,
            client_state: params.state.clone(),
            nonce: params.nonce.clone(),
            code_challenge: params.code_challenge.clone(),
            code_challenge_method: params.challenge_method(),
            prompt: params.prompt.clone(),
            max_age: params.max_age,
            login_hint: params.login_hint.clone(),
        })
        .await?;

    // prompt=login: 忽略当前 session，强制重新登录
    if crate::service::oauth::has_prompt(params.prompt.as_deref(), "login") {
        return pending_redirect(&state, &jar, auth_request.id).await;
    }

    resolve_authorization(&state, &jar, &auth_request).await
}

/// GET /oauth2/authorize/resume
///
/// 登录成功后的恢复入口：
/// login/social callback → 302 到此接口 → consume nonce cookie → 加载 auth_request →
/// 进入 resolve_authorization
///
/// 安全设计：不直接从 URL 读取 request_id，而是通过 nonce cookie
/// 消费 Redis pending request 获取 auth_request_id，防止 request_id 被枚举
pub async fn resume(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Response), OAuthError> {
    let cookies = state.cookie_factory();
    let nonce_name = cookies.nonce_cookie_name();
    let nonce =
        jar.get(&nonce_name)
            .map(|c| c.value().to_owned())
            .ok_or(OAuthError::BadRequest(
                "Missing authentication nonce".to_owned(),
            ))?;

    let oauth = state.oauth_service();
    let auth_request_id = oauth
        .consume_pending_request(&nonce)
        .await
        .map_err(OAuthError::Internal)?
        .ok_or(OAuthError::BadRequest(
            "Invalid or expired pending request".to_owned(),
        ))?;

    let auth_request = authorization_requests::Entity::find_by_id(auth_request_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            OAuthError::Internal(
                pero_error::AppError::internal("db_error", "Database error").with_source(e),
            )
        })?
        .ok_or(OAuthError::BadRequest(
            "Authorization request not found".to_owned(),
        ))?;

    if auth_request.completed_at.is_some() {
        return Err(OAuthError::BadRequest(
            "Authorization request already completed".to_owned(),
        ));
    }

    let now = time::OffsetDateTime::now_utc();
    if auth_request.expires_at < now {
        return Err(OAuthError::BadRequest(
            "Authorization request expired".to_owned(),
        ));
    }

    let clear = cookies.clear_cookie(&nonce_name);

    resolve_authorization(&state, &jar.add(clear), &auth_request).await
}

/// 授权决策逻辑（authorize 和 resume 共享）
///
/// 根据当前 session 状态决定下一步：
/// - 无 session → 存 pending request + 跳转 /sso/login
/// - 有 session + 无 app access → redirect_uri?error=access_denied
/// - 有 session + prompt=consent → 强制跳转 /sso/consent（不检查已有 consent）
/// - 有 session + 已 consent → 生成 authorization code → 302 redirect_uri?code=xxx
/// - 有 session + 未 consent → 设 pero_auth_req cookie → 302 /sso/consent
async fn resolve_authorization(
    state: &AppState,
    jar: &CookieJar,
    auth_request: &authorization_requests::Model,
) -> Result<(CookieJar, Response), OAuthError> {
    let session = extract_session(state, jar)
        .await
        .map_err(|_| OAuthError::Unavailable)?;

    let Some(session) = session else {
        return pending_redirect(state, jar, auth_request.id).await;
    };

    if crate::service::oauth::requires_reauthentication(
        auth_request.prompt.as_deref(),
        auth_request.max_age,
        session.authenticated_at,
        session.created_at,
        auth_request.created_at,
        time::OffsetDateTime::now_utc(),
    ) {
        return pending_redirect(state, jar, auth_request.id).await;
    }

    let oauth = state.oauth_service();

    if !oauth
        .check_app_access(session.user_id, auth_request.app_id)
        .await?
    {
        return Err(OAuthError::redirect(
            &auth_request.redirect_uri,
            "access_denied",
            Some("User does not have access to this application"),
            auth_request.client_state.as_deref(),
        ));
    }

    // prompt=consent 强制展示 consent 页面，忽略已有 consent 记录
    let force_consent =
        crate::service::oauth::has_prompt(auth_request.prompt.as_deref(), "consent");
    let has_consent = if force_consent {
        false
    } else {
        oauth
            .check_consent(
                session.user_id,
                auth_request.client_id,
                &auth_request.scopes,
            )
            .await?
    };

    if has_consent {
        let code = oauth
            .issue_auth_code_with_consent(auth_request.id, &session, false)
            .await?;
        let redirect = pero_utils::oauth::url::build_code_redirect_url(
            &auth_request.redirect_uri,
            &code,
            auth_request.client_state.as_deref(),
        );
        Ok((jar.clone(), Redirect::to(&redirect).into_response()))
    } else {
        let cookies = state.cookie_factory();
        let req_cookie_name = cookies.auth_req_cookie_name();
        let cookie_value = AuthReqCookieValue {
            auth_request_id: auth_request.id,
            user_id: session.user_id,
        };
        let cookie = cookies.build_short_lived_cookie(
            &req_cookie_name,
            &cookies
                .encode_auth_request(&cookie_value)
                .unwrap_or_default(),
            state.config.oauth2.auth_code_ttl_seconds,
        );
        Ok((
            jar.clone().add(cookie),
            Redirect::to("/sso/consent").into_response(),
        ))
    }
}

/// 将 authorization_request 存入 Redis pending，设 nonce cookie，跳转 /sso/login
pub(crate) async fn pending_redirect(
    state: &AppState,
    jar: &CookieJar,
    auth_request_id: Uuid,
) -> Result<(CookieJar, Response), OAuthError> {
    let oauth = state.oauth_service();
    let nonce = oauth.store_pending_request(auth_request_id).await?;
    let cookies = state.cookie_factory();
    let nonce_name = cookies.nonce_cookie_name();
    let cookie = cookies.build_short_lived_cookie(
        &nonce_name,
        &nonce,
        state.config.oauth2.auth_code_ttl_seconds,
    );
    Ok((
        jar.clone().add(cookie),
        Redirect::to("/sso/login").into_response(),
    ))
}

/// 将 validator 校验错误转换为 OAuthError
///
/// - redirect_uri 为空 → 400 BadRequest（无法构造重定向）
/// - redirect_uri 非空 → redirect_uri?error=invalid_request
fn report_into_oauth_error(
    errors: validator::ValidationErrors,
    params: &AuthorizeQuery,
) -> OAuthError {
    if params.redirect_uri.trim().is_empty() {
        return OAuthError::BadRequest("Missing required query parameters".to_owned());
    }
    let msg = errors.to_string();
    OAuthError::BadRequest(msg)
}
