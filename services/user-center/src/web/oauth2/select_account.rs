use crate::{
    db::entity::{authorization_requests, users},
    service::{
        oauth::{OAuthService, has_prompt},
        session::SessionService,
    },
    state::app::AppState,
    web::{session::extract_browser_session, util},
};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Choice {
    account_choice_request_id: Uuid,
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
    let session = extract_browser_session(state, &jar)
        .await
        .map_err(|_| crate::web::error::OAuthError::Unavailable)?;
    let token = pero_utils::crypto::encode_signed_json(
        &Choice {
            account_choice_request_id: id,
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
    session_id: Option<Uuid>,
) -> Result<authorization_requests::Model, Box<Response>> {
    let choice: Choice = pero_utils::crypto::decode_signed_json(raw, key(state))
        .map_err(|_| pero_api_axum::json_error("invalid_request"))?;
    if choice.session_id != session_id {
        return Err(Box::new(pero_api_axum::json_error("invalid_request")));
    }
    authorization_requests::Entity::find_by_id(choice.account_choice_request_id)
        .one(&state.db)
        .await
        .map_err(util::dependency_error)?
        .filter(|r| {
            r.completed_at.is_none()
                && r.expires_at > time::OffsetDateTime::now_utc()
                && has_prompt(r.prompt.as_deref(), "select_account")
        })
        .ok_or_else(|| Box::new(pero_api_axum::json_error("invalid_request")))
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<Params>,
) -> Response {
    let session = match extract_browser_session(&state, &jar).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if !params.token.is_empty()
        && let Err(e) = request(&state, &params.token, session.as_ref().map(|s| s.id)).await
    {
        return *e;
    }
    let username = if let Some(s) = session.filter(|s| !s.recovery_pending) {
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
    let choose_other = input.action == "other";
    if input.token.is_empty() {
        if !choose_other {
            return Redirect::to(&util::safe_redirect(&input.redirect)).into_response();
        }
        let jar = match switch(&state, jar).await {
            Ok(j) => j,
            Err(e) => return *e,
        };
        let mut url = "/account/login".to_string();
        pero_utils::encode::append_query_param(
            &mut url,
            "redirect",
            &util::safe_redirect(&input.redirect),
        );
        return (jar, Redirect::to(&url)).into_response();
    }
    let session = match extract_browser_session(&state, &jar).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let session_id = session.as_ref().map(|s| s.id);
    let request = match request(&state, &input.token, session_id).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let mut prompts = request
        .prompt
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|p| *p != "select_account")
        .collect::<Vec<_>>();
    if choose_other && !prompts.contains(&"login") {
        prompts.push("login");
    }
    let prompt = (!prompts.is_empty()).then(|| prompts.join(" "));
    if choose_other {
        return switch_for_authorization(&state, &jar, session_id, request, prompt)
            .await
            .unwrap_or_else(|response| *response);
    }
    let Some(session) = session.filter(|s| !s.recovery_pending) else {
        return pero_api_axum::json_error("invalid_request");
    };
    let updated = match async {
        let txn = state
            .oauth_service()
            .begin_authorization_choice(&request, session.id, session.user_id)
            .await
            .map_err(super::authorize::pending_form_error)?;
        let updated = consume_choice(&txn, request, prompt).await?;
        txn.commit().await.map_err(util::dependency_error)?;
        Ok::<_, Box<Response>>(updated)
    }
    .await
    {
        Ok(r) => r,
        Err(e) => return *e,
    };
    super::authorize::resolve_pending_authorization(&state, &jar, &updated, true)
        .await
        .into_response()
}

async fn consume_choice<C: ConnectionTrait>(
    db: &C,
    request: authorization_requests::Model,
    prompt: Option<String>,
) -> Result<authorization_requests::Model, Box<Response>> {
    // Consume the choice once, even when two tabs submit different actions.
    authorization_requests::Model::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE authorization_requests SET prompt=$2 WHERE id=$1 AND prompt=$3
         AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING *",
        [request.id.into(), prompt.into(), request.prompt.into()],
    ))
    .one(db)
    .await
    .map_err(util::dependency_error)?
    .ok_or_else(|| Box::new(pero_api_axum::json_error("invalid_request")))
}

async fn switch_for_authorization(
    state: &AppState,
    jar: &CookieJar,
    session_id: Option<Uuid>,
    request: authorization_requests::Model,
    prompt: Option<String>,
) -> Result<Response, Box<Response>> {
    let txn = state.db.begin().await.map_err(util::dependency_error)?;
    OAuthService::lock_pending_authorization_policy(&txn, &request)
        .await
        .map_err(super::authorize::pending_form_error)?;
    // Match issuance's lock order: session before authorization request.
    if let Some(session_id) = session_id
        && !SessionService::revoke_login_state_in_db(&txn, session_id, "account_switch")
            .await
            .map_err(util::dependency_error)?
    {
        return Err(Box::new(pero_api_axum::json_error("invalid_request")));
    }
    let updated = consume_choice(&txn, request, prompt).await?;
    // Store the continuation only after the request passes validation, and before commit.
    let (jar, response) = super::authorize::pending_redirect(state, jar, updated.id)
        .await
        .map_err(IntoResponse::into_response)?;
    txn.commit().await.map_err(util::dependency_error)?;
    Ok((clear_session_cookie(state, jar), response).into_response())
}
pub(crate) async fn switch(state: &AppState, jar: CookieJar) -> Result<CookieJar, Box<Response>> {
    // Switching must also revoke incomplete MFA and recovery sessions. The
    // authenticated extractor intentionally excludes these browser credentials.
    let session = extract_browser_session(state, &jar)
        .await
        .map_err(IntoResponse::into_response)?;
    if let Some(session) = session {
        state
            .session_service()
            .revoke_login_state(session.id, "account_switch")
            .await
            .map_err(util::dependency_error)?;
    }
    Ok(clear_session_cookie(state, jar))
}

pub(super) fn clear_session_cookie(state: &AppState, jar: CookieJar) -> CookieJar {
    let cookies = state.cookie_factory();
    jar.add(cookies.clear_cookie(cookies.session_cookie_name()))
}
