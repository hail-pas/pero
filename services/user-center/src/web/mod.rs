pub mod account;
pub mod dashboard;
pub mod error;
pub mod home;
pub mod login_flow;
pub mod oauth2;
pub mod open;
pub mod security;
pub mod session;
pub mod sso;
pub mod util;

use askama::Template;
use axum::Router;
use axum::response::{Html, IntoResponse, Response};

pub fn routes(state: crate::state::app::AppState) -> Router<crate::state::app::AppState> {
    Router::new()
        .route("/", axum::routing::get(home::home))
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(open::openid_configuration),
        )
        .merge(oauth2::routes())
        .merge(sso::routes())
        .merge(account::routes())
        .merge(dashboard::routes(state))
}

pub async fn not_found() -> Response {
    let tpl = sso::template::ErrorTemplate {
        code: "404".to_owned(),
    };
    match tpl.render() {
        Ok(html) => (axum::http::StatusCode::NOT_FOUND, Html(html)).into_response(),
        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}
