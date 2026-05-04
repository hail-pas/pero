use crate::shared::state::AppState;
use axum::Router;
use axum::routing::{get, post};

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/oauth2/authorize",
            get(crate::handler::oauth2::authorize::authorize),
        )
        .route(
            "/oauth2/session/end",
            get(crate::handler::oidc::session::end_session),
        )
        .route(
            "/.well-known/openid-configuration",
            get(crate::handler::oidc::discovery::discovery),
        )
        .route("/oauth2/keys", get(crate::handler::oidc::jwks::jwks))
}

pub fn login_required_routes() -> Router<AppState> {
    Router::new().route(
        "/oauth2/userinfo",
        get(crate::handler::oidc::userinfo::userinfo),
    )
}

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/oauth2/clients",
            post(crate::handler::oauth2::client_management::create_client)
                .get(crate::handler::oauth2::client_management::list_clients),
        )
        .route(
            "/api/oauth2/clients/{id}",
            get(crate::handler::oauth2::client_management::get_client)
                .put(crate::handler::oauth2::client_management::update_client)
                .delete(crate::handler::oauth2::client_management::delete_client),
        )
}
