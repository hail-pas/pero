use crate::domain::abac::resource::{AbacContextExt, Action, Resource};
use crate::shared::state::AppState;
use axum::Router;
use axum::routing::{delete, get, post, put};

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/social-providers/enabled",
            get(crate::handler::social::public::list_enabled_providers),
        )
        .route(
            "/sso/social/{provider}/login",
            get(crate::handler::social::initiate::social_login),
        )
        .route(
            "/sso/social/{provider}/callback",
            get(crate::handler::social::callback::social_callback),
        )
        .route(
            "/sso/social/{provider}/bind-callback",
            get(crate::handler::social::callback::social_bind_callback),
        )
}

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/social-providers",
            post(crate::handler::social::management::create_provider)
                .abac_context(Resource::SocialProvider, Action::Create),
        )
        .route(
            "/api/social-providers",
            get(crate::handler::social::management::list_providers)
                .abac_context(Resource::SocialProvider, Action::List),
        )
        .route(
            "/api/social-providers/{id}",
            get(crate::handler::social::management::get_provider)
                .abac_context(Resource::SocialProvider, Action::Read),
        )
        .route(
            "/api/social-providers/{id}",
            put(crate::handler::social::management::update_provider)
                .abac_context(Resource::SocialProvider, Action::Update),
        )
        .route(
            "/api/social-providers/{id}",
            delete(crate::handler::social::management::delete_provider)
                .abac_context(Resource::SocialProvider, Action::Delete),
        )
}
