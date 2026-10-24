pub mod account;
pub mod dashboard;
pub mod error;
pub mod home;
pub mod login_flow;
pub mod oauth2;
pub mod open;
pub mod security;
pub mod security_gate;
pub mod session;
pub mod sso;
pub mod util;

use axum::Router;
use axum::response::{IntoResponse, Response};

pub fn routes(state: crate::state::app::AppState) -> Router<crate::state::app::AppState> {
    let directory = state.config.frontend.static_dir.clone();
    let pages = Router::new()
        .route("/", axum::routing::get(home::home))
        .merge(sso::routes())
        .merge(account::routes())
        .merge(dashboard::routes(state.clone()))
        .route_layer(axum::middleware::from_fn(move |req, next| {
            let directory = directory.clone();
            async move { pero_api_axum::spa::serve_page(req, next, directory).await }
        }));

    Router::new()
        .merge(pages)
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(open::openid_configuration),
        )
        .merge(oauth2::routes())
        .merge(sso::social_routes())
        .layer(axum::middleware::from_fn_with_state(
            state,
            security_gate::gate,
        ))
}

pub async fn not_found() -> Response {
    let tpl = sso::dto::ErrorView {
        code: "404".to_owned(),
    };
    (
        axum::http::StatusCode::NOT_FOUND,
        pero_api_axum::form::view("ErrorView", tpl),
    )
        .into_response()
}
