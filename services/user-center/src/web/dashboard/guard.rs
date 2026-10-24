use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::EntityTrait;

use crate::db::entity::users;
use crate::db::enums::UserStatus;
use crate::state::app::AppState;
use crate::state::session::SsoSession;
use crate::web::dashboard::dto::DashboardLayout;
use crate::web::session::extract_session;

#[derive(Clone)]
pub struct AdminContext {
    pub session: SsoSession,
    pub user: users::Model,
}

impl FromRequestParts<AppState> for AdminContext {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AdminContext>()
            .cloned()
            .ok_or_else(|| Redirect::to("/account/login?redirect=/dashboard").into_response())
    }
}

pub struct AdminPage {
    pub layout: DashboardLayout,
    pub jar: CookieJar,
    pub csrf_token: String,
}

impl AdminPage {
    pub fn new(state: &AppState, jar: CookieJar, admin: AdminContext) -> Self {
        let layout = DashboardLayout::from_user(&admin.user);
        let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
        Self {
            layout,
            jar,
            csrf_token,
        }
    }
}

pub async fn require_admin_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    jar: CookieJar,
    mut req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Redirect::to("/account/login?redirect=/dashboard").into_response(),
        Err(status) => return status.into_response(),
    };

    let user = match find_active_user(&state.db, session.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Redirect::to("/account/login?redirect=/dashboard").into_response(),
        Err(error) => {
            tracing::error!(%error, "Admin user lookup failed");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    match crate::service::security::role(&state.db, user.id).await {
        Ok(Some(role)) if role == "super_admin" => {}
        Ok(_) => return render_forbidden("forbidden"),
        Err(e) => return crate::web::util::dependency_error(e),
    }
    match crate::service::security::mfa_enabled(&state.db, user.id).await {
        Ok(true) => {}
        Ok(false) => return Redirect::to("/account/security").into_response(),
        Err(e) => return crate::web::util::dependency_error(e),
    }
    use sea_orm::{ColumnTrait, QueryFilter};
    let assurance = crate::db::helper::session::active_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
    )
    .filter(crate::db::entity::sso_sessions::Column::Id.eq(session.id))
    .one(&state.db)
    .await;
    match assurance {
        Ok(Some(s)) if s.mfa_verified_at.is_some() => {}
        Ok(_) => return Redirect::to("/sso/mfa").into_response(),
        Err(e) => return crate::web::util::dependency_error(e),
    }
    req.extensions_mut().insert(AdminContext {
        session,
        user: user.clone(),
    });
    super::audit::run(&state, req, &user, next).await
}

async fn find_active_user(
    db: &sea_orm::DatabaseConnection,
    user_id: uuid::Uuid,
) -> Result<Option<users::Model>, sea_orm::DbErr> {
    Ok(users::Entity::find_by_id(user_id)
        .one(db)
        .await?
        .filter(|u| u.status == UserStatus::Active && u.deleted_at.is_none()))
}

pub async fn is_dashboard_admin(
    db: &sea_orm::DatabaseConnection,
    user_id: uuid::Uuid,
) -> Result<bool, sea_orm::DbErr> {
    Ok(crate::service::security::role(db, user_id).await?.is_some())
}

fn render_forbidden(code: &str) -> Response {
    let tpl = super::dto::ForbiddenView {
        code: code.to_owned(),
    };
    (
        axum::http::StatusCode::FORBIDDEN,
        pero_api_axum::form::view("ForbiddenView", tpl),
    )
        .into_response()
}
