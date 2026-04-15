pub mod auth;
pub mod health;
pub mod policies;
pub mod user_attrs;
pub mod users;

use axum::Router;
use crate::state::AppState;
use crate::middleware;

pub fn build_router(state: AppState) -> Router {
    use axum::routing::{get, post};

    // === Public routes: no auth required ===
    let public = Router::new()
        .route("/health", get(health::health))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh));

    // === Auth-only routes: login required, no ABAC check ===
    let auth_only = Router::new()
        .route("/auth/logout", post(auth::logout))
        .route("/api/users/{id}/attributes", get(user_attrs::list_attributes).put(user_attrs::set_attributes))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ));

    // === Full authorization routes: auth + ABAC ===
    let authorized = Router::new()
        .route("/api/users", post(users::create_user).get(users::list_users))
        .route("/api/users/{id}", get(users::get_user).put(users::update_user).delete(users::delete_user))
        .route("/api/policies", post(policies::create_policy).get(policies::list_policies))
        .route("/api/policies/{id}", get(policies::get_policy).put(policies::update_policy).delete(policies::delete_policy))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::abac::abac_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ));

    // Merge all groups, apply state once, then shared outer layers
    Router::new()
        .merge(public)
        .merge(auth_only)
        .merge(authorized)
        .with_state(state)
        .layer(axum::middleware::from_fn(middleware::request_id::add_request_id))
        .layer(axum::middleware::from_fn(middleware::logging::request_logging))
}
