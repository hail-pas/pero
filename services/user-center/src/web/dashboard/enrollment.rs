use super::guard::{AdminContext, AdminPage};
use crate::{
    service::{ManagementError, enrollment as svc},
    state::app::AppState,
    web::util,
};
use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;
#[derive(Deserialize)]
pub struct PolicyForm {
    csrf_token: String,
    app: Option<Uuid>,
    mode: String,
    #[serde(default)]
    domains: String,
    #[serde(default)]
    approval_required: bool,
    #[serde(default)]
    emergency_stop: bool,
    #[serde(default)]
    inherit: bool,
    version: i64,
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Query(scope): Query<svc::ListQuery>,
) -> Response {
    let page = AdminPage::new(&state, jar, admin);
    let result = async {
        let mut policy = svc::policy(&state.db, scope.app).await?;
        let inherited = scope.app.is_some() && policy.app_id.is_none();
        policy.app_id = scope.app;
        let can_invite = svc::supports_personal_enrollment(&state.db, scope.app).await?;
        let list = svc::list(&state.db, &scope, None).await?;
        Ok::<_, ManagementError>((policy, inherited, can_invite, list))
    }
    .await;
    match result {
        Ok((policy, inherited, can_invite, list)) => util::view_response(
            "EnrollmentAdminView",
            serde_json::json!({"layout":page.layout,"csrf_token":page.csrf_token,"policy":policy,
                "inherited":inherited,"can_invite":can_invite,"rows":list.rows,"page":list.page,
                "total_pages":list.total_pages,"pending_count":list.pending_count}),
            page.jar,
        ),
        Err(e) => util::management_response(Err(e)),
    }
}

pub async fn save(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Form(f): Form<PolicyForm>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    util::management_response(
        svc::save_policy(
            &state,
            &admin.actor(&state),
            svc::Policy {
                app_id: f.app,
                mode: f.mode,
                domains: util::parse_comma_list(&f.domains),
                approval_required: f.approval_required,
                emergency_stop: f.emergency_stop,
                version: f.version,
            },
            f.inherit,
        )
        .await,
    )
}
#[derive(Deserialize)]
pub struct Invite {
    csrf_token: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    delivery: svc::InvitationDelivery,
    app: Option<Uuid>,
    #[serde(default)]
    domain_exception: bool,
    #[serde(default)]
    reason: String,
}
pub async fn invite(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Form(f): Form<Invite>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    activation_response(
        svc::invite(
            &state,
            &f.email,
            f.app,
            &admin.actor(&state),
            f.domain_exception,
            &f.reason,
            f.delivery,
        )
        .await,
    )
}
#[derive(Deserialize)]
pub struct Decision {
    csrf_token: String,
    action: String,
    #[serde(default)]
    reason: String,
}
pub async fn manage(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Decision>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    activation_response(svc::manage(&state, &admin.actor(&state), id, &f.action, &f.reason).await)
}

pub(super) fn activation_response(result: Result<Option<String>, ManagementError>) -> Response {
    match result {
        Ok(Some(link)) => pero_api_axum::json_ok_with_sensitive(
            serde_json::json!({"secret":link,"purpose":"invitation_activation"}),
        ),
        result => util::management_response(result.map(|_| ())),
    }
}
