use crate::shared::middleware;
use crate::shared::state::AppState;
use axum::Router;

pub fn build_router(state: AppState) -> Router {
    use axum::routing::{get, post};

    let public = Router::new()
        .route("/health", get(crate::routes::health::health))
        .route(
            "/auth/login",
            post(crate::domains::identity::routes::login::login),
        )
        .route(
            "/auth/refresh",
            post(crate::domains::identity::routes::login::refresh),
        );

    let auth_only = Router::new()
        .route(
            "/auth/logout",
            post(crate::domains::identity::routes::login::logout),
        )
        .route(
            "/api/users/{id}/attributes",
            get(crate::routes::user_attrs::list_attributes)
                .put(crate::routes::user_attrs::set_attributes),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ));

    let authorized = Router::new()
        .route(
            "/api/users",
            post(crate::domains::identity::routes::registration::create_user)
                .get(crate::domains::identity::routes::profile::list_users),
        )
        .route(
            "/api/users/{id}",
            get(crate::domains::identity::routes::profile::get_user)
                .put(crate::domains::identity::routes::profile::update_user)
                .delete(crate::domains::identity::routes::profile::delete_user),
        )
        .route(
            "/api/policies",
            post(crate::routes::policies::create_policy)
                .get(crate::routes::policies::list_policies),
        )
        .route(
            "/api/policies/{id}",
            get(crate::routes::policies::get_policy)
                .put(crate::routes::policies::update_policy)
                .delete(crate::routes::policies::delete_policy),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::abac::abac_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ));

    let identity = Router::new()
        .route(
            "/api/identity/register",
            post(crate::domains::identity::routes::registration::register),
        )
        .route(
            "/api/identity/login",
            post(crate::domains::identity::routes::login::login),
        )
        .route(
            "/api/users/me",
            get(crate::domains::identity::routes::profile::get_me)
                .put(crate::domains::identity::routes::profile::update_me),
        );

    Router::new()
        .merge(public)
        .merge(auth_only)
        .merge(authorized)
        .merge(identity)
        .with_state(state)
        .layer(axum::middleware::from_fn(
            middleware::request_id::add_request_id,
        ))
        .layer(axum::middleware::from_fn(
            middleware::logging::request_logging,
        ))
}
