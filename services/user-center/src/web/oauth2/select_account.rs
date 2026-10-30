use crate::{
    db::entity::{authorization_requests, users},
    service::oauth::has_prompt,
    state::app::AppState,
    web::{session::extract_session, util},
};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Choice {
    request_id: Uuid,
    session_id: Option<Uuid>,
}
#[derive(Default, Deserialize)]
pub struct Params {
    #[serde(default)]
    token: String,
    #[serde(default)]
    redirect: String,
}
#[derive(Deserialize)]
pub struct Input {
    csrf_token: String,
    #[serde(default)]
    token: String,
    action: String,
    #[serde(default)]
    redirect: String,
}
fn key(state: &AppState) -> &[u8] {
    state
        .config
        .sso
        .cookie_signing_secret
        .expose_secret()
        .as_bytes()
}
pub async fn redirect(
    state: &AppState,
    jar: CookieJar,
    id: Uuid,
) -> Result<(CookieJar, Response), crate::web::error::OAuthError> {
    let session = extract_session(state, &jar)
        .await
        .map_err(|_| crate::web::error::OAuthError::Unavailable)?;
    let token = pero_utils::crypto::encode_signed_json(
        &Choice {
            request_id: id,
            session_id: session.map(|s| s.id),
        },
        key(state),
    )
    .map_err(|_| crate::web::error::OAuthError::Unavailable)?;
    let mut url = "/sso/select-account".to_string();
    pero_utils::encode::append_query_param(&mut url, "token", &token);
    Ok((jar, Redirect::to(&url).into_response()))
}
async fn request(
    state: &AppState,
    raw: &str,
) -> Result<(Choice, authorization_requests::Model), Response> {
    let choice: Choice = pero_utils::crypto::decode_signed_json(raw, key(state))
        .map_err(|_| pero_api_axum::json_error("invalid_request"))?;
    let request = authorization_requests::Entity::find_by_id(choice.request_id)
        .one(&state.db)
        .await
        .map_err(util::dependency_error)?
        .filter(|r| {
            r.completed_at.is_none()
                && r.expires_at > time::OffsetDateTime::now_utc()
                && has_prompt(r.prompt.as_deref(), "select_account")
        })
        .ok_or_else(|| pero_api_axum::json_error("invalid_request"))?;
    Ok((choice, request))
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<Params>,
) -> Response {
    if !params.token.is_empty()
        && let Err(e) = request(&state, &params.token).await
    {
        return e;
    }
    let session = match extract_session(&state, &jar).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let username = if let Some(s) = session {
        match users::Entity::find_by_id(s.user_id).one(&state.db).await {
            Ok(Some(u)) => u.username,
            Ok(None) => String::new(),
            Err(e) => return util::dependency_error(e),
        }
    } else {
        String::new()
    };
    state.web_security().view_with_csrf(jar,"SelectAccountView",|csrf_token|serde_json::json!({"csrf_token":csrf_token,"token":params.token,"username":username,"redirect":util::safe_redirect(&params.redirect)}))
}
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<Input>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return e;
    }
    if !matches!(input.action.as_str(), "current" | "other") {
        return pero_api_axum::json_error("invalid_request");
    }
    if input.token.is_empty() {
        if input.action == "current" {
            return Redirect::to(&util::safe_redirect(&input.redirect)).into_response();
        }
        let jar = match switch(&state, jar).await {
            Ok(j) => j,
            Err(e) => return e,
        };
        let mut url = "/account/login".to_string();
        pero_utils::encode::append_query_param(
            &mut url,
            "redirect",
            &util::safe_redirect(&input.redirect),
        );
        return (jar, Redirect::to(&url)).into_response();
    }
    let (choice, request) = match request(&state, &input.token).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if input.action == "current" {
        let session = match extract_session(&state, &jar).await {
            Ok(s) => s,
            Err(e) => return e.into_response(),
        };
        if session.is_none() || session.as_ref().map(|s| s.id) != choice.session_id {
            return pero_api_axum::json_error("invalid_request");
        }
    }
    let mut prompts = request
        .prompt
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|p| *p != "select_account")
        .map(String::from)
        .collect::<Vec<_>>();
    if input.action == "other" && !prompts.iter().any(|p| p == "login") {
        prompts.push("login".into());
    }
    let mut active: authorization_requests::ActiveModel = request.into();
    active.prompt = Set((!prompts.is_empty()).then(|| prompts.join(" ")));
    let updated = match active.update(&state.db).await {
        Ok(r) => r,
        Err(e) => return util::dependency_error(e),
    };
    let result = if input.action == "other" {
        let jar = match switch(&state, jar).await {
            Ok(j) => j,
            Err(e) => return e,
        };
        super::authorize::pending_redirect(&state, &jar, updated.id).await
    } else {
        super::authorize::resolve_authorization(&state, &jar, &updated).await
    };
    match result {
        Ok(v) => v.into_response(),
        Err(e) => e.into_response(),
    }
}
pub(super) async fn switch(state: &AppState, jar: CookieJar) -> Result<CookieJar, Response> {
    // Switching must also revoke incomplete MFA and recovery sessions. The
    // authenticated extractor intentionally excludes these browser credentials.
    let session = crate::web::session::extract_browser_session(state, &jar)
        .await
        .map_err(IntoResponse::into_response)?;
    if let Some(session) = session {
        state
            .session_service()
            .revoke_login_state(session.id, "account_switch")
            .await
            .map_err(util::dependency_error)?;
    }
    let cookies = state.cookie_factory();
    Ok(jar.add(cookies.clear_cookie(cookies.session_cookie_name())))
}
