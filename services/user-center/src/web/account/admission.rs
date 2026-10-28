use super::{dto::AccountLayout, security::AccountContext};
use crate::{state::app::AppState, web::util};
use axum::{
    Form,
    extract::{Path, State},
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
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
) -> Response {
    let rows=AppRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT a.id,a.name,u.status::text AS status FROM apps a LEFT JOIN user_app_access u ON u.app_id=a.id AND u.user_id=$1 WHERE NOT a.system AND a.status='active' ORDER BY a.name",[account.user.id.into()])).all(&state.db).await;
    match rows {
        Ok(rows) => {
            let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
            util::view_response(
                "AdmissionView",
                serde_json::json!({"layout":AccountLayout::from_user(&state.db,&account.user).await,"csrf_token":csrf_token,"rows":rows,"username":account.user.username}),
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
