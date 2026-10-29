use super::guard::{AdminContext, AdminPage};
use crate::{
    db::entity::sso_sessions,
    state::app::AppState,
    web::{account::security::SessionRow, util},
};
use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use sea_orm::{ColumnTrait, PaginatorTrait, QueryFilter, QueryOrder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ListQuery {
    page: Option<u64>,
}
#[derive(Serialize)]
struct UserSecurityView {
    layout: super::dto::DashboardLayout,
    csrf_token: String,
    user: super::dto::UserSummary,
    login_lock: crate::service::login::LoginLockStatus,
    rows: Vec<SessionRow>,
    mfa_enabled: bool,
    can_recover: bool,
    page: u64,
    total_pages: u64,
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Response {
    let result = async {
        let user = crate::db::helper::admin::find_user_by_id(&state.db, id)
            .await?
            .filter(|u| u.deleted_at.is_none())
            .ok_or(crate::service::ManagementError::Invalid("not_found"))?;
        let login_lock = crate::service::login::LoginService::new(&state.db, &state.cache)
            .lock_status(id)
            .await?;
        let mfa_enabled = crate::service::security::mfa_enabled(&state.db, id).await?;
        let can_recover = mfa_enabled
            && id != admin.user.id
            && user.status == crate::db::enums::UserStatus::Active;
        let page = query.page.unwrap_or(1).max(1);
        let pages = crate::db::helper::session::valid_query(
            time::OffsetDateTime::now_utc(),
            state.config.sso.session_idle_ttl_seconds,
        )
        .filter(sso_sessions::Column::UserId.eq(id))
        .order_by_desc(sso_sessions::Column::CreatedAt)
        .order_by_desc(sso_sessions::Column::Id)
        .paginate(&state.db, crate::config::DASHBOARD_PAGE_SIZE);
        let total_pages = pages.num_pages().await?;
        let rows = pages
            .fetch_page(page - 1)
            .await?
            .into_iter()
            .map(|s| SessionRow::new(s, admin.session.id))
            .collect();
        let AdminPage {
            layout,
            csrf_token,
            jar,
        } = AdminPage::new(&state, jar, admin);
        Ok::<_, crate::service::ManagementError>((
            UserSecurityView {
                layout,
                csrf_token,
                user: user.into(),
                login_lock,
                mfa_enabled,
                can_recover,
                rows,
                page,
                total_pages,
            },
            jar,
        ))
    }
    .await;
    match result {
        Ok((view, jar)) => util::view_response("UserSecurityView", view, jar),
        Err(e) => util::management_response(Err(e)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    csrf_token: String,
    action: String,
    session_id: Option<Uuid>,
    reason: String,
}
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(input): Form<Input>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return response;
    }
    if input.action == "recover_mfa" {
        return match crate::service::recovery::issue_assisted_recovery(
            &state,
            &admin.session,
            id,
            &input.reason,
        )
        .await
        {
            Ok(code) => pero_api_axum::json_ok_with_sensitive(
                serde_json::json!({"secret":code,"purpose":"mfa_recovery"}),
            ),
            Err(e) => util::management_response(Err(e)),
        };
    }
    util::management_response(
        crate::service::admin_sessions::change(
            &state,
            &admin.session,
            id,
            &input.action,
            input.session_id,
            &input.reason,
        )
        .await,
    )
}
