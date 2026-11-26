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
    organization_admission: bool,
    organization_only: bool,
    self_service_open: bool,
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
    let eligibility = crate::service::tenant_context::AUTO_ELIGIBILITY;
    let rows = AppRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        format!("SELECT a.id,a.name,a.code,a.description,a.homepage_url,a.logo_url,
            a.tenant_mode='organization' AS organization_only,
            COALESCE(p.mode,platform.mode)='self_service' AND NOT platform.emergency_stop AS self_service_open,
            COALESCE(u.require_mfa,false) AS require_mfa,
            COALESCE(u.admission_origin='organization',false) AS organization_admission,
            CASE WHEN u.status='active' AND u.admission_origin='organization' AND NOT ({eligibility}) THEN NULL ELSE u.status::text END AS status
            FROM apps a
            JOIN registration_policies platform ON platform.id='00000000-0000-0000-0000-000000000000'
            LEFT JOIN registration_policies p ON p.app_id=a.id
            LEFT JOIN user_app_access u ON u.app_id=a.id AND u.user_id=$1
            WHERE NOT a.system AND a.status='active' ORDER BY a.name"),
        [account.user.id.into()],
    ))
    .all(&state.db)
    .await;
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
    #[serde(default)]
    recovery: String,
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
    let result = match f.action.as_str() {
        "leave" => crate::service::account_security::leave_app(&state, &account.session, id).await,
        "join" => {
            let source = match crate::web::oauth2::access::enrollment_source(
                &state,
                &f.recovery,
                account.session.id,
                id,
            )
            .await
            {
                Ok(source) => source,
                Err(error) => return util::management_response(Err(error)),
            };
            crate::service::enrollment::start_portal(&state, &account.session, id, source).await
        }
        _ => Err(crate::service::ManagementError::Invalid("invalid_request")),
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
        Ok(()) => (
            state.web_security().clear_login_cookies(jar),
            Redirect::to("/account/login?closed=1"),
        )
            .into_response(),
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
        Ok(Some(token)) => crate::web::sso::register::enter_enrollment(&state, jar, token).await,
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
