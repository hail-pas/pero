use axum::extract::{Path, State};
use axum::response::Response;
use axum_extra::extract::CookieJar;
use pero_api_axum::{json_ok, json_ok_with_sensitive};

use super::dto::{ClientSettingsForm, CreateClientForm};
use crate::db::enums::OauthClientType;
use crate::service::{
    ManagementError,
    client::{self, ClientInput},
};
use crate::state::app::AppState;
use crate::web::util::{self, CsrfOnly};

fn client_input(form: ClientSettingsForm) -> Result<ClientInput, ManagementError> {
    Ok(ClientInput {
        client_type: OauthClientType::try_from_str(&form.client_type)
            .map_err(|_| ManagementError::Invalid("invalid_client_type"))?,
        secret: form.secret.trim().to_owned(),
        name: util::empty_or_opt(&form.name),
        redirect_uris: util::parse_lines(&form.redirect_uris),
        post_logout_redirect_uris: util::parse_lines(&form.post_logout_redirect_uris),
        scopes: util::parse_comma_list(&form.scopes),
        grant_types: util::parse_comma_list(&form.grant_types),
        require_pkce: form.require_pkce,
        access_token_ttl: form.access_token_ttl,
        refresh_token_ttl: form.refresh_token_ttl,
        id_token_ttl: form.id_token_ttl,
    })
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<CreateClientForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let app_id = form.app_id;
    let identifier = form.identifier.clone();
    let input = match client_input(form.into()) {
        Ok(input) => input,
        Err(error) => return util::management_response(Err(error)),
    };
    match client::create(&state.db, app_id, identifier.trim(), input).await {
        Ok(Some(secret)) => json_ok_with_sensitive(serde_json::json!({"secret":secret})),
        Ok(None) => json_ok(),
        Err(error) => util::management_response(Err(error)),
    }
}

pub async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<ClientSettingsForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let input = match client_input(form) {
        Ok(input) => input,
        Err(error) => return util::management_response(Err(error)),
    };
    util::management_response(client::update(&state.db, id, input).await)
}

pub async fn reset_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    match client::reset_secret(&state.db, id).await {
        Ok(secret) => json_ok_with_sensitive(serde_json::json!({"secret":secret})),
        Err(error) => util::management_response(Err(error)),
    }
}

pub async fn toggle_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(client::toggle_status(&state.db, id).await)
}

#[derive(serde::Deserialize)]
pub struct Rotation {
    csrf_token: String,
    grace_seconds: i64,
}
pub async fn rotate_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<Rotation>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return e;
    }
    match client::rotate_secret(&state.db, id, form.grace_seconds).await {
        Ok(secret) => json_ok_with_sensitive(serde_json::json!({"secret":secret})),
        Err(e) => util::management_response(Err(e)),
    }
}
pub async fn retire_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return e;
    }
    util::management_response(client::retire_secret(&state.db, id).await)
}
