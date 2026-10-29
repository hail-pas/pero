use super::guard::{AdminContext, AdminPage};
use crate::{
    db::{
        entity::{apps, users},
        enums::UserStatus,
    },
    service::{ManagementError, access},
    state::app::AppState,
    web::util,
};
use axum::{
    Extension, Form,
    extract::{Path, Query, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbBackend, EntityTrait, FromQueryResult, QueryFilter, Set,
    Statement,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Default, Deserialize)]
pub struct Search {
    page: Option<u64>,
    #[serde(default)]
    q: String,
    #[serde(default)]
    status: String,
}
#[derive(Serialize, FromQueryResult)]
struct Member {
    user_id: Uuid,
    username: String,
    nickname: Option<String>,
    status: String,
}
pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Query(query): Query<Search>,
) -> Response {
    let app = match apps::Entity::find_by_id(id).one(&state.db).await {
        Ok(Some(app)) => app,
        Ok(None) => return axum::http::StatusCode::NOT_FOUND.into_response(),
        Err(e) => return util::dependency_error(e),
    };
    if !matches!(query.status.as_str(), "" | "active" | "disabled") {
        return pero_api_axum::json_error("invalid_request");
    }
    let page = query.page.unwrap_or(1).clamp(1, 1_000_000);
    let values: Vec<sea_orm::Value> = vec![id.into(), query.q.trim().into(), query.status.into()];
    let filter = "FROM user_app_access a JOIN users u ON u.id=a.user_id WHERE a.app_id=$1 AND u.deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM admin_roles r WHERE r.user_id=u.id) AND ($2='' OR strpos(lower(u.username::text),lower($2))>0 OR strpos(lower(COALESCE(u.nickname,'')),lower($2))>0) AND ($3='' OR a.status::text=$3)";
    let result=async {
        #[derive(FromQueryResult)] struct Count { total:i64 }
        let total=Count::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT count(*) AS total {filter}"),values.clone())).one(&state.db).await?.map(|v|v.total).unwrap_or(0);
        let mut values=values;values.extend([(crate::config::DASHBOARD_PAGE_SIZE as i64).into(),(((page-1)*crate::config::DASHBOARD_PAGE_SIZE) as i64).into()]);
        let rows=Member::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT u.id AS user_id,u.username::text,u.nickname,a.status::text {filter} ORDER BY a.created_at DESC,u.id DESC LIMIT $4 OFFSET $5"),values)).all(&state.db).await?;
        Ok::<_,sea_orm::DbErr>((rows,(total as u64).div_ceil(crate::config::DASHBOARD_PAGE_SIZE)))
    }.await;
    let p = AdminPage::new(&state, jar, admin);
    match result {
        Ok((rows, total_pages)) => util::view_response(
            "AppMembersView",
            serde_json::json!({"layout":p.layout,"csrf_token":p.csrf_token,"app_id":id,"app_name":app.name,"system":app.system,"rows":rows,"page":page,"total_pages":total_pages}),
            p.jar,
        ),
        Err(e) => util::dependency_error(e),
    }
}
use axum::response::IntoResponse;
#[derive(Deserialize)]
pub struct Change {
    csrf_token: String,
    action: String,
    #[serde(default)]
    username: String,
    user_id: Option<Uuid>,
}
pub async fn change(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path(id): Path<Uuid>,
    Extension(audit): Extension<super::audit::AuditId>,
    Form(f): Form<Change>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    if f.action == "grant" {
        let key = match pero_cache_redis::rate_limit_key::rl_admin_members
            .key(&admin.session.user_id.to_string())
        {
            Ok(k) => k,
            Err(e) => return util::dependency_error(e),
        };
        match pero_cache_redis::enforce_rate_limit(&state.cache, &key, 30).await {
            Ok(()) => {}
            Err(pero_cache_redis::RateLimitError::Denied { .. }) => {
                return util::management_response(Err(ManagementError::Invalid("rate_limited")));
            }
            Err(e) => return util::dependency_error(e),
        }
    }
    let result = async {
        let app = apps::Entity::find_by_id(id)
            .one(&state.db)
            .await?
            .ok_or(ManagementError::Invalid("not_found"))?;
        if app.system {
            return Err(ManagementError::Invalid("forbidden"));
        }
        let user_id = match f.action.as_str() {
            "grant" => {
                users::Entity::find()
                    .filter(users::Column::Username.eq(f.username.trim()))
                    .filter(users::Column::DeletedAt.is_null())
                    .filter(users::Column::Status.eq(UserStatus::Active))
                    .one(&state.db)
                    .await?
                    .ok_or(ManagementError::Invalid("not_found"))?
                    .id
            }
            "revoke" => f
                .user_id
                .ok_or(ManagementError::Invalid("invalid_request"))?,
            _ => return Err(ManagementError::Invalid("invalid_request")),
        };
        // Record the resolved member before the mutation; do not retain the submitted form.
        crate::db::entity::audit_events::ActiveModel {
            id: Set(audit.0),
            target: Set(format!("/dashboard/apps/{id}/members/{user_id}")),
            ..Default::default()
        }
        .update(&state.db)
        .await?;
        if f.action == "grant" {
            access::grant_app(&state.db, &admin.actor(&state), user_id, id).await
        } else {
            access::revoke_app(&state.db, &admin.actor(&state), user_id, id).await
        }
    }
    .await;
    util::management_response(result)
}
