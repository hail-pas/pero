use axum::extract::{Path, State};
use axum::response::Response;
use axum_extra::extract::CookieJar;

use super::dto::KeyForm;
use crate::db::enums::{KeyAlgorithm, KeyUse};
use crate::service::{
    ManagementError,
    keys::{self, KeyInput},
};
use crate::state::app::AppState;
use crate::web::util::{self, CsrfOnly};

fn parse_datetime(value: &str) -> Result<Option<time::OffsetDateTime>, ManagementError> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    time::OffsetDateTime::parse(value.trim(), &time::format_description::well_known::Rfc3339)
        .map(Some)
        .map_err(|_| ManagementError::Invalid("invalid_key_dates"))
}

fn key_input(form: KeyForm) -> Result<KeyInput, ManagementError> {
    Ok(KeyInput {
        kid: form.kid.trim().to_owned(),
        algorithm: KeyAlgorithm::try_from_str(&form.algorithm)
            .map_err(|_| ManagementError::Invalid("invalid_algorithm"))?,
        key_use: KeyUse::try_from_str(&form.key_use)
            .map_err(|_| ManagementError::Invalid("invalid_key_use"))?,
        public_key_pem: form.public_key_pem.trim().to_owned(),
        private_key_pem: util::empty_or_opt(&form.private_key_pem),
        certificate_pem: util::empty_or_opt(&form.certificate_pem),
        not_before: parse_datetime(&form.not_before)?,
        expires_at: parse_datetime(&form.expires_at)?,
        active: form.active,
    })
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<KeyForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let input = match key_input(form) {
        Ok(input) => input,
        Err(error) => return util::management_response(Err(error)),
    };
    util::management_response(keys::create(&state.db, &admin.actor(&state), id, input).await)
}

pub async fn activate(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path((id, kid)): Path<(uuid::Uuid, String)>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(keys::activate(&state.db, &admin.actor(&state), id, &kid).await)
}

pub async fn revoke(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path((id, kid)): Path<(uuid::Uuid, String)>,
    axum::Form(form): axum::Form<RevokeForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(if form.emergency {
        keys::emergency_revoke(&state.db, &admin.actor(&state), id, &kid).await
    } else {
        keys::revoke(&state.db, &admin.actor(&state), id, &kid).await
    })
}

#[derive(serde::Deserialize)]
pub struct ScheduleForm {
    csrf_token: String,
    activate_at: String,
}
pub async fn schedule(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path((id, kid)): Path<(uuid::Uuid, String)>,
    axum::Form(form): axum::Form<ScheduleForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    if form.activate_at.trim().is_empty() {
        return util::management_response(
            keys::cancel_schedule(&state.db, &admin.actor(&state), id, &kid).await,
        );
    }
    let at = match parse_datetime(&form.activate_at) {
        Ok(Some(at)) => at,
        _ => return util::management_response(Err(ManagementError::Invalid("invalid_key_dates"))),
    };
    util::management_response(keys::schedule(&state.db, &admin.actor(&state), id, &kid, at).await)
}

#[derive(serde::Deserialize)]
pub struct RevokeForm {
    csrf_token: String,
    #[serde(default)]
    emergency: bool,
}
