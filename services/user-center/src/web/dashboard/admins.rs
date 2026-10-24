use crate::{state::app::AppState, web::util};
use axum::{Form, extract::State, response::Response};
use axum_extra::extract::CookieJar;
use sea_orm::{DbBackend, FromQueryResult, Statement};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Serialize, FromQueryResult)]
struct Row {
    user_id: Uuid,
    username: String,
    role: String,
}
#[derive(Deserialize)]
pub struct Input {
    csrf_token: String,
    username: String,
    role: String,
}
pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
) -> Response {
    let rows=Row::find_by_statement(Statement::from_string(DbBackend::Postgres,"SELECT r.user_id,u.username,r.role FROM admin_roles r JOIN users u ON u.id=r.user_id ORDER BY u.username".to_string())).all(&state.db).await;
    match rows {
        Ok(rows) => {
            let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
            util::view_response(
                "AdminRolesView",
                serde_json::json!({"rows":rows,"csrf_token":csrf_token,"layout":super::dto::DashboardLayout::from_user(&admin.user)}),
                jar,
            )
        }
        Err(e) => util::dependency_error(e),
    }
}
pub async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Form(input): Form<Input>,
) -> Response {
    if let Some(r) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return r;
    }
    util::management_response(
        crate::service::admin::update_role(
            &state.db,
            &admin.session,
            state.config.sso.session_idle_ttl_seconds,
            &input.username,
            &input.role,
        )
        .await,
    )
}
