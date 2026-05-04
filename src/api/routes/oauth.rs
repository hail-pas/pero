use crate::domain::abac::resource::{AbacContextExt, Action, Resource};
use crate::shared::state::AppState;
use axum::routing::{delete, get, post, put};
use axum::Router;

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
                .abac_context(Resource::OAuth2Client, Action::Create),
        )
        .route(
            "/api/oauth2/clients",
            get(crate::handler::oauth2::client_management::list_clients)
                .abac_context(Resource::OAuth2Client, Action::List),
        )
        .route(
            "/api/oauth2/clients/{id}",
            get(crate::handler::oauth2::client_management::get_client)
                .abac_context(Resource::OAuth2Client, Action::Read),
        )
        .route(
            "/api/oauth2/clients/{id}",
            put(crate::handler::oauth2::client_management::update_client)
                .abac_context(Resource::OAuth2Client, Action::Update),
        )
        .route(
            "/api/oauth2/clients/{id}",
            delete(crate::handler::oauth2::client_management::delete_client)
                .abac_context(Resource::OAuth2Client, Action::Delete),
        )
}
