//! Authenticated self-service organization routes.
use crate::{
    service::tenant as svc,
    state::app::AppState,
    web::{
        account::{dto::AccountLayout, security::AccountContext},
        util,
    },
};
use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;
#[derive(Deserialize)]
pub struct Create {
    csrf_token: String,
    name: String,
    slug: String,
}
#[derive(Deserialize)]
pub struct Rename {
    csrf_token: String,
    name: String,
}
#[derive(Deserialize)]
pub struct Change {
    csrf_token: String,
    action: String,
}
#[derive(Deserialize)]
pub struct Invite {
    csrf_token: String,
    email: String,
    role: String,
}
#[derive(Deserialize)]
pub struct OnlyCsrf {
    csrf_token: String,
}
fn checked(jar: &CookieJar, csrf: &str, s: &AppState) -> Option<Response> {
    util::verify_csrf_or_json_error(jar, csrf, s)
}
pub async fn list(State(s): State<AppState>, jar: CookieJar, a: AccountContext) -> Response {
    let rows = match svc::list(&s.db, a.user.id).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let layout = match AccountLayout::from_user(&s.db, &a.user).await {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let policy = match crate::service::tenant_policy::read(&s.db, a.user.id).await {
        Ok(policy) => policy,
        Err(error) => return util::management_response(Err(error)),
    };
    let (jar, csrf_token) = s.web_security().ensure_csrf(jar);
    util::view_response(
        "TenantListView",
        serde_json::json!({"layout":layout,"csrf_token":csrf_token,"tenants":rows,"creation_policy":policy}),
        jar,
    )
}
pub async fn create(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Form(f): Form<Create>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    match svc::create(&s.db, a.user.id, &f.name, &f.slug).await {
        Ok(id) => axum::Json(serde_json::json!({"redirect":format!("/account/tenants/{id}")}))
            .into_response(),
        Err(error) => util::management_response(Err(error)),
    }
}
pub async fn detail(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(id): Path<Uuid>,
) -> Response {
    let tenant = match svc::get(&s.db, a.user.id, id).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let members = if tenant.kind == "organization" {
        match svc::members(&s.db, a.user.id, id).await {
            Ok(v) => v,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        Vec::new()
    };
    let invitations =
        if matches!(tenant.role.as_str(), "owner" | "admin") && tenant.kind == "organization" {
            match svc::invitations(&s.db, a.user.id, id).await {
                Ok(v) => v,
                Err(e) => return util::management_response(Err(e)),
            }
        } else {
            Vec::new()
        };
    let layout = match AccountLayout::from_user(&s.db, &a.user).await {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let can_invite = if tenant.kind == "organization" {
        match svc::can_invite(&s.db, id).await {
            Ok(v) => v,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        false
    };
    let (jar, csrf_token) = s.web_security().ensure_csrf(jar);
    util::view_response(
        "TenantDetailView",
        serde_json::json!({"layout":layout,"csrf_token":csrf_token,"tenant":tenant,"members":members,"invitations":invitations,"current_user_id":a.user.id,"can_invite":can_invite}),
        jar,
    )
}
pub async fn rename(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Rename>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::rename(&s.db, a.user.id, id, &f.name).await)
}
pub async fn member(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path((id, user)): Path<(Uuid, Uuid)>,
    Form(f): Form<Change>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::update_member(&s.db, a.user.id, id, user, &f.action).await)
}
pub async fn leave(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<OnlyCsrf>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    match svc::leave(&s.db, a.user.id, id).await {
        Ok(()) => axum::Json(serde_json::json!({"redirect": "/account/tenants"})).into_response(),
        Err(error) => util::management_response(Err(error)),
    }
}
pub async fn invite(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Invite>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::invite(&s, a.user.id, id, &f.email, &f.role).await)
}
pub async fn revoke_invite(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path((id, invitation)): Path<(Uuid, Uuid)>,
    Form(f): Form<OnlyCsrf>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::revoke_invite(&s.db, a.user.id, id, invitation).await)
}
pub async fn invitation(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(token): Path<String>,
) -> Response {
    let invite = match svc::invitation(&s.db, &token).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let layout = match AccountLayout::from_user(&s.db, &a.user).await {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let (jar, csrf_token) = s.web_security().ensure_csrf(jar);
    util::view_response(
        "TenantInvitationView",
        serde_json::json!({"layout":layout,"csrf_token":csrf_token,"invitation":invite,"verified_email":a.user.email_verified_at.is_some(),"user_email":a.user.email}),
        jar,
    )
}
pub async fn accept(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(token): Path<String>,
    Form(f): Form<OnlyCsrf>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::accept(&s.db, a.user.id, &token).await)
}

pub async fn toggle_status(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<OnlyCsrf>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::toggle_status(&s.db, a.user.id, id).await)
}

pub async fn members(
    State(s): State<AppState>,
    a: AccountContext,
    Path(id): Path<Uuid>,
) -> Response {
    match svc::members(&s.db, a.user.id, id).await {
        Ok(rows) => axum::Json(serde_json::json!({"rows":rows})).into_response(),
        Err(error) => util::management_response(Err(error)),
    }
}
pub async fn invitations(
    State(s): State<AppState>,
    a: AccountContext,
    Path(id): Path<Uuid>,
) -> Response {
    match svc::invitations(&s.db, a.user.id, id).await {
        Ok(rows) => axum::Json(serde_json::json!({"rows":rows})).into_response(),
        Err(error) => util::management_response(Err(error)),
    }
}

/// Organization dissolution requires its exact slug, not an unconfirmed click.
pub async fn delete(
    State(s): State<AppState>,
    jar: CookieJar,
    a: AccountContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Delete>,
) -> Response {
    if let Some(e) = checked(&jar, &f.csrf_token, &s) {
        return e;
    }
    match svc::delete(&s.db, a.user.id, id, &f.confirmation).await {
        Ok(()) => axum::Json(serde_json::json!({"redirect": "/account/tenants"})).into_response(),
        Err(error) => util::management_response(Err(error)),
    }
}

#[derive(Deserialize)]
pub struct Delete {
    csrf_token: String,
    confirmation: String,
}
