use super::{dto::AccountLayout, security::AccountContext};
use crate::{state::app::AppState, web::util};
use axum::{
    Form,
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{DbBackend, FromQueryResult, Statement};
use serde::Deserialize;
use uuid::Uuid;
#[derive(serde::Serialize, FromQueryResult)]
struct AppRow {
    id: Uuid,
    name: String,
    status: Option<String>,
    code: String,
    description: Option<String>,
    homepage_url: Option<String>,
    logo_url: Option<String>,
    require_mfa: bool,
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Query(query): Query<crate::service::enrollment::ListQuery>,
) -> Response {
    let rows=AppRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT a.id,a.name,a.code,a.description,a.homepage_url,a.logo_url,COALESCE(u.require_mfa,false) AS require_mfa,u.status::text AS status FROM apps a LEFT JOIN user_app_access u ON u.app_id=a.id AND u.user_id=$1 WHERE NOT a.system AND a.status='active' ORDER BY a.name",[account.user.id.into()])).all(&state.db).await;
    match rows {
        Ok(rows) => {
            let progress = match crate::service::enrollment::list(
                &state.db,
                &query,
                Some(&account.user),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return util::management_response(Err(e)),
            };
            let mfa_enabled =
                match crate::service::security::mfa_enabled(&state.db, account.user.id).await {
                    Ok(v) => v,
                    Err(e) => return util::dependency_error(e),
                };
            let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
            let layout = match AccountLayout::from_user(&state.db, &account.user).await {
                Ok(layout) => layout,
                Err(error) => return util::dependency_error(error),
            };
            util::view_response(
                "AdmissionView",
                serde_json::json!({"layout":layout,"csrf_token":csrf_token,"rows":rows,"mfa_enabled":mfa_enabled,"username":account.user.username,"progress":progress}),
                jar,
            )
        }
        Err(e) => util::dependency_error(e),
    }
}
#[derive(Deserialize)]
pub struct Action {
    csrf_token: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    confirmation: String,
}
pub async fn app(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Action>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    let result = if f.action == "leave" {
        crate::service::account_security::leave_app(&state, &account.session, id).await
    } else {
        crate::service::enrollment::start(
            &state,
            account.user.email.as_deref().unwrap_or(""),
            Some(id),
            None,
        )
        .await
    };
    util::management_response(result)
}
pub async fn close(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Form(f): Form<Action>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    match crate::service::account_security::close_account(&state, &account.session, &f.confirmation)
        .await
    {
        Ok(()) => {
            let cookies = state.cookie_factory();
            (
                jar.add(cookies.clear_cookie(cookies.session_cookie_name())),
                Redirect::to("/account/login?closed=1"),
            )
                .into_response()
        }
        Err(e) => util::management_response(Err(e)),
    }
}

pub async fn progress_action(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Action>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    match crate::service::enrollment::owner_action(&state, &account.session, id, &f.action).await {
        Ok(Some(token)) => (
            jar.add(crate::web::sso::register::flow_cookie(&state, token)),
            Redirect::to("/sso/register"),
        )
            .into_response(),
        Ok(None) => pero_api_axum::json_ok(),
        Err(e) => util::management_response(Err(e)),
    }
}

/// This endpoint takes its owner exclusively from the authenticated account.
pub async fn mfa(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Action>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    let required = match f.action.as_str() {
        "enable_mfa" => true,
        "disable_mfa" => false,
        _ => return pero_api_axum::json_error("invalid_request"),
    };
    util::management_response(
        crate::service::account_security::set_app_mfa(&state, &account.session, id, required).await,
    )
}
