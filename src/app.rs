use crate::shared::middleware;
use crate::shared::state::AppState;
use axum::Router;

pub fn build_router(state: AppState) -> Router {
    use axum::routing::{get, post};

    let public = Router::new()
        .route("/health", get(crate::routes::health::health))
        .route("/auth/login", post(crate::routes::auth::login))
        .route("/auth/refresh", post(crate::routes::auth::refresh));

    let auth_only = Router::new()
        .route("/auth/logout", post(crate::routes::auth::logout))
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
            post(crate::routes::users::create_user).get(crate::routes::users::list_users),
        )
        .route(
            "/api/users/{id}",
            get(crate::routes::users::get_user)
                .put(crate::routes::users::update_user)
                .delete(crate::routes::users::delete_user),
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
            get(crate::domains::identity::routes::profile::get_profile)
                .put(crate::domains::identity::routes::profile::update_profile),
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
