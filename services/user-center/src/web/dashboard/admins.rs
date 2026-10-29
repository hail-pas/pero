use crate::{state::app::AppState, web::util};
use axum::response::IntoResponse;
use axum::{
    Form,
    extract::{Query, State},
    response::Response,
};
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
#[derive(Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    role: String,
    page: Option<u64>,
}

pub async fn search_users(
    State(state): State<AppState>,
    admin: super::guard::AdminContext,
    Query(query): Query<ListQuery>,
) -> Response {
    #[derive(Serialize, FromQueryResult)]
    struct User {
        id: Uuid,
        username: String,
    }
    let q = query.q.trim();
    if q.is_empty() {
        return axum::Json(serde_json::json!({"users":[]})).into_response();
    }
    match User::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id,username::text FROM users WHERE id<>$2 AND deleted_at IS NULL AND status='active' AND strpos(lower(username::text),lower($1))>0 ORDER BY username LIMIT 20", [q.into(), admin.user.id.into()])).all(&state.db).await {
        Ok(users) => axum::Json(serde_json::json!({"users":users})).into_response(),
        Err(e) => util::dependency_error(e),
    }
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Query(query): Query<ListQuery>,
) -> Response {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = crate::config::DASHBOARD_PAGE_SIZE;
    let filter = "FROM admin_roles r JOIN users u ON u.id=r.user_id WHERE ($1='' OR strpos(lower(u.username::text),lower($1))>0) AND ($2='' OR r.role=$2)";
    #[derive(FromQueryResult)]
    struct Count {
        total: i64,
    }
    let values: Vec<sea_orm::Value> = vec![query.q.trim().into(), query.role.into()];
    let total = match Count::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        format!("SELECT count(*) AS total {filter}"),
        values.clone(),
    ))
    .one(&state.db)
    .await
    {
        Ok(Some(c)) => c.total as u64,
        Ok(None) => 0,
        Err(e) => return util::dependency_error(e),
    };
    let mut values = values;
    values.extend([page_size.into(), ((page - 1) * page_size).into()]);
    let rows=Row::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT r.user_id,u.username::text,r.role {filter} ORDER BY u.username,r.user_id LIMIT $3 OFFSET $4"),values)).all(&state.db).await;
    match rows {
        Ok(rows) => {
            let mut values = Vec::new();
            for row in rows {
                let grants = if row.role == "admin" {
                    match crate::service::permissions::load(&state.db, row.user_id).await {
                        Ok(a) => Some(a.grants),
                        Err(e) => return util::management_response(Err(e)),
                    }
                } else {
                    None
                };
                values.push(serde_json::json!({"user_id":row.user_id,"username":row.username,"role":row.role,"grants":grants}));
            }
            let apps = match crate::db::helper::admin::list_all_apps_brief(&state.db, None).await {
                Ok(a) => a,
                Err(e) => return util::dependency_error(e),
            };

            let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
            util::view_response(
                "AdminRolesView",
                serde_json::json!({"rows":values,"current_user_id":admin.user.id,"page":page,"total_pages":total.div_ceil(page_size),"catalog":crate::service::permissions::catalog(),"apps":apps,"csrf_token":csrf_token,"layout":super::guard::AdminPage::new(&state,jar.clone(),admin).layout}),
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

pub async fn catalog() -> Response {
    axum::Json(crate::service::permissions::catalog()).into_response()
}
pub async fn permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    axum::Extension(audit): axum::Extension<super::audit::AuditId>,
    axum::Json(input): axum::Json<crate::service::permissions::Replace>,
) -> Response {
    if let Some(r) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return r;
    }
    util::management_response(
        crate::service::permissions::replace(&state.db, &admin.actor(&state), id, input, audit.0)
            .await,
    )
}
