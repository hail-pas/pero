use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::domain::oauth2::store::RefreshTokenRepo;
use crate::handler::account::common;
use crate::handler::account::common::{ClientView, user_display_name, user_initial};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "account/authorizations.html")]
pub struct AuthorizationsTemplate {
    pub active: String,
    pub user_initial: String,
    pub user_name: String,
    pub clients: Vec<ClientView>,
}

pub async fn authorizations_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let auths = RefreshTokenRepo::list_active_by_user(&state.db, user.id).await?;
    let clients: Vec<ClientView> = auths
        .iter()
        .map(|a| ClientView {
            client_name: a.client_name.clone(),
            scopes: a.scopes.join(", "),
            created_at: a.created_at.format("%Y-%m-%d %H:%M").to_string(),
        })
        .collect();

    let tpl = AuthorizationsTemplate {
        active: "authorizations".into(),
        user_initial: user_initial(&user),
        user_name: user_display_name(&user),
        clients,
    };
    Ok(common::render_tpl(&tpl)?.into_response())
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token_id: String,
}

pub async fn revoke_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<RevokeForm>,
) -> Result<Response, AppError> {
    let user_id = common::get_account_user_id(&state, &headers).await?;
    let token_id: uuid::Uuid = form
        .token_id
        .parse()
        .map_err(|_| AppError::BadRequest("invalid token id".into()))?;
    RefreshTokenRepo::revoke_for_user(&state.db, token_id, user_id).await?;
    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "Authorization revoked.",
    ))
    .into_response())
}
