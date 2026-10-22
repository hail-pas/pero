use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};

use crate::middleware::CurrentUser;
use crate::state::AppState;

pub async fn home(State(state): State<AppState>, user: CurrentUser) -> Response {
    let issuer = &state.config.oauth2.issuer;
    let template = crate::handler::templates::HomeTemplate {
        username: user.username.clone(),
        email: user.email.clone().unwrap_or_default(),
        picture: user.picture.clone().unwrap_or_default(),
        profile_url: format!("{}/account/profile", issuer),
        password_url: format!("{}/account/change-password", issuer),
        issuer: issuer.clone(),
    };
    template
        .render()
        .map(|html| Html(html).into_response())
        .unwrap_or_else(|err| {
            tracing::error!(error = %err, "home template render failed");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
            )
                .into_response()
        })
}
