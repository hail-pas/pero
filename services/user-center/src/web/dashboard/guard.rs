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
    pub access: crate::service::permissions::Access,
}

impl AdminContext {
    pub fn actor(&self, state: &AppState) -> crate::service::permissions::Actor {
        crate::service::permissions::Actor {
            session: self.session.clone(),
            idle_ttl_seconds: state.config.sso.session_idle_ttl_seconds,
        }
    }
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
        let mut layout = DashboardLayout::for_dashboard(&admin.user);
        layout.has_visible_apps = admin.access.super_admin
            || !admin
                .access
                .app_ids(crate::service::permissions::Permission::AppsRead)
                .is_empty();
        layout.admin_access = Some(admin.access);
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

    match crate::service::admin::can_access_dashboard(&state.db, user.id).await {
        Ok(true) => {}
        Ok(_) => return render_forbidden("forbidden"),
        Err(e) => return crate::web::util::dependency_error(e),
    }
    match crate::service::security::mfa_enabled(&state.db, user.id).await {
        Ok(true) => {}
        Ok(false) => return admin_challenge("/account/security", req.uri()),
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
        Ok(_) => return admin_challenge("/sso/mfa", req.uri()),
        Err(e) => return crate::web::util::dependency_error(e),
    }
    let access = match crate::service::permissions::load(&state.db, user.id).await {
        Ok(a) => a,
        Err(e) => return crate::web::util::management_response(Err(e)),
    };
    req.extensions_mut().insert(AdminContext {
        access,
        session,
        user: user.clone(),
    });
    super::audit::run(&state, req, &user, next).await
}

fn admin_challenge(path: &str, uri: &axum::http::Uri) -> Response {
    let mut target = path.to_owned();
    pero_utils::encode::append_query_param(&mut target, "redirect", &uri.to_string());
    Redirect::to(&target).into_response()
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

#[derive(Clone, Copy)]
enum Policy {
    Dashboard,
    Global(crate::service::permissions::Permission),
    UserEdit,
    App(crate::service::permissions::Permission),
    Client(crate::service::permissions::Permission),
    SubmittedApp,
    Super,
}

/// Every registered method must have an explicit policy; unknown routes fail closed.
fn policy(path: &str, read: bool) -> Option<Policy> {
    use crate::service::permissions::Permission as P;
    Some(match (path, read) {
        ("/dashboard", true) | ("/dashboard/apps", true) => Policy::Dashboard,
        ("/dashboard/users", true) | ("/dashboard/users/{id}", true) => {
            Policy::Global(P::UsersRead)
        }
        ("/dashboard/users/new", _) => Policy::Global(P::UsersCreate),
        ("/dashboard/users/{id}/edit", _) => Policy::UserEdit,
        ("/dashboard/users/{id}/set-status", false) => Policy::Global(P::UsersStatusUpdate),
        ("/dashboard/users/{id}/reset-password", false) => Policy::Global(P::UsersPasswordReset),
        ("/dashboard/users/{id}/grant-app", false)
        | ("/dashboard/users/{id}/revoke-app", false)
        | ("/dashboard/clients/new", false) => Policy::SubmittedApp,
        ("/dashboard/apps/{id}", true) => Policy::App(P::AppsRead),
        ("/dashboard/apps/{id}/edit", _) | ("/dashboard/apps/{id}/toggle", false) => {
            Policy::App(P::AppsManage)
        }
        ("/dashboard/apps/{id}/members", true) => Policy::App(P::AppsMembersRead),
        ("/dashboard/apps/{id}/members", false) => Policy::App(P::AppsMembersManage),
        ("/dashboard/clients/{id}/edit", false)
        | ("/dashboard/clients/{id}/toggle", false)
        | ("/dashboard/clients/{id}/backchannel-logout", false) => Policy::Client(P::ClientsManage),
        ("/dashboard/clients/{id}/reset-secret", false)
        | ("/dashboard/clients/{id}/rotate-secret", false)
        | ("/dashboard/clients/{id}/retire-secret", false) => {
            Policy::Client(P::ClientsSecretRotate)
        }
        ("/dashboard/providers", true) | ("/dashboard/providers/{id}", true) => {
            Policy::Global(P::ProvidersRead)
        }
        ("/dashboard/events", true) => Policy::Global(P::EventsRead),
        ("/dashboard/audit", true) | ("/dashboard/audit/{id}", true) => {
            Policy::Global(P::AuditRead)
        }
        ("/dashboard/notifications", true) => Policy::Global(P::NotificationsRead),
        ("/dashboard/notifications/{id}/retry", false) => Policy::Global(P::NotificationsRetry),
        ("/dashboard/admins", _)
        | ("/dashboard/admins/users", true)
        | ("/dashboard/admins/permission-catalog", true)
        | ("/dashboard/admins/{id}/permissions", false)
        | ("/dashboard/apps/new", _)
        | ("/dashboard/registration", _)
        | ("/dashboard/invitations", false)
        | ("/dashboard/enrollments/{id}", false)
        | ("/dashboard/apps/{id}/integration", _)
        | ("/dashboard/users/{id}/security", _)
        | ("/dashboard/clients/{id}/account-sync", false)
        | ("/dashboard/account-sync-deliveries/{id}/retry", false)
        | ("/dashboard/logout-deliveries/{id}/retry", false)
        | ("/dashboard/providers/new", _)
        | ("/dashboard/providers/{id}/edit", _)
        | ("/dashboard/providers/{id}/toggle", false)
        | ("/dashboard/providers/{id}/keys/new", false)
        | ("/dashboard/providers/{id}/keys/{kid}/activate", false)
        | ("/dashboard/providers/{id}/keys/{kid}/schedule", false)
        | ("/dashboard/providers/{id}/keys/{kid}/revoke", false) => Policy::Super,
        _ => return None,
    })
}

/// Runs inside the audit wrapper so authenticated authorization failures are recorded.
pub async fn require_permission(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    use crate::service::{
        ManagementError,
        permissions::{self, Permission as P},
    };
    use axum::http::Method;
    let admin = req
        .extensions()
        .get::<AdminContext>()
        .expect("admin middleware");
    let path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|v| v.as_str())
        .unwrap_or("");
    let read = req.method() == Method::GET || req.method() == Method::HEAD;
    let write = req.method() == Method::POST;
    let id = req
        .uri()
        .path()
        .split('/')
        .nth(3)
        .and_then(|v| uuid::Uuid::parse_str(v).ok());
    let result = async {
        if !read && !write {
            return Err(ManagementError::Invalid("forbidden"));
        }
        let access = &admin.access;
        match policy(path, read).ok_or(ManagementError::Invalid("forbidden"))? {
            Policy::Dashboard | Policy::SubmittedApp => {} // mutation services check submitted application IDs
            Policy::Global(p) => access.require_global(p)?,
            Policy::UserEdit => {
                if !access.can_global(P::UsersUpdate) && !access.can_global(P::UsersContactUpdate) {
                    return Err(ManagementError::Invalid("forbidden"));
                }
            }
            Policy::App(p) => {
                permissions::app(
                    &state.db,
                    access,
                    id.ok_or(ManagementError::Invalid("not_found"))?,
                    p,
                )
                .await?
            }
            Policy::Client(p) => {
                let client = crate::db::entity::oauth_clients::Entity::find_by_id(
                    id.ok_or(ManagementError::Invalid("not_found"))?,
                )
                .one(&state.db)
                .await?
                .ok_or(ManagementError::Invalid("not_found"))?;
                permissions::app(&state.db, access, client.app_id, p).await?;
            }
            Policy::Super => {
                if !access.super_admin {
                    return Err(ManagementError::Invalid("forbidden"));
                }
            }
        }
        if path.starts_with("/dashboard/users/{id}") {
            permissions::protect_user(
                &state.db,
                access,
                id.ok_or(ManagementError::Invalid("not_found"))?,
            )
            .await?;
        }
        Ok::<_, ManagementError>(())
    }
    .await;
    let mut response = match result {
        Ok(()) => next.run(req).await,
        Err(e) => crate::web::util::management_response(Err(e)),
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub async fn index(
    admin: AdminContext,
    axum::extract::State(state): axum::extract::State<AppState>,
    jar: CookieJar,
) -> Response {
    use crate::service::permissions::Permission as P;
    let a = &admin.access;
    let path = if a.super_admin || !a.app_ids(P::AppsRead).is_empty() {
        Some("/dashboard/apps")
    } else {
        [
            (P::UsersRead, "/dashboard/users"),
            (P::ProvidersRead, "/dashboard/providers"),
            (P::EventsRead, "/dashboard/events"),
            (P::NotificationsRead, "/dashboard/notifications"),
            (P::AuditRead, "/dashboard/audit"),
        ]
        .into_iter()
        .find(|(p, _)| a.can_global(*p))
        .map(|(_, p)| p)
    };
    if let Some(path) = path {
        return Redirect::to(path).into_response();
    }
    let p = AdminPage::new(&state, jar, admin);
    crate::web::util::view_response(
        "DashboardEmptyView",
        serde_json::json!({"layout":p.layout,"csrf_token":p.csrf_token}),
        p.jar,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_registered_dashboard_method_declares_a_policy() {
        // Read the actual route registrations so adding a route without a policy fails validation.
        for route in include_str!("mod.rs").split(".route(").skip(1) {
            let path = route.split('"').nth(1).expect("literal dashboard path");
            for (handler, read) in [("get(", true), ("post(", false)] {
                if route.contains(handler) {
                    assert!(
                        super::policy(path, read).is_some(),
                        "missing policy: {handler} {path}"
                    );
                }
            }
        }
        assert!(super::policy("/dashboard/undeclared", true).is_none());
        assert!(super::policy("/dashboard/undeclared", false).is_none());
    }
}
