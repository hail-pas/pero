pub mod apps;
pub mod audit;
pub mod clients;
pub mod dto;
pub mod guard;
pub mod keys;
pub mod providers;
pub mod users;

use axum::Router;
use axum::middleware;
use axum::response::Redirect;
use axum::routing::{get, post};

use crate::state::app::AppState;
use guard::require_admin_middleware;

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/dashboard/audit", get(audit::list))
        .route(
            "/dashboard/events",
            get(crate::web::account::security::admin_activity),
        )
        .route(
            "/dashboard",
            get(|| async { Redirect::to("/dashboard/apps") }),
        )
        .route("/dashboard/apps", get(apps::list))
        .route(
            "/dashboard/apps/new",
            get(apps::new_form).post(apps::create),
        )
        .route("/dashboard/apps/{id}", get(apps::detail))
        .route(
            "/dashboard/apps/{id}/edit",
            get(apps::edit_form).post(apps::update),
        )
        .route("/dashboard/apps/{id}/toggle", post(apps::toggle_status))
        .route("/dashboard/clients/new", post(clients::create))
        .route("/dashboard/clients/{id}/edit", post(clients::update))
        .route(
            "/dashboard/clients/{id}/reset-secret",
            post(clients::reset_secret),
        )
        .route(
            "/dashboard/clients/{id}/toggle",
            post(clients::toggle_status),
        )
        .route("/dashboard/users", get(users::list))
        .route(
            "/dashboard/users/new",
            get(users::new_form).post(users::create),
        )
        .route("/dashboard/users/{id}", get(users::detail))
        .route(
            "/dashboard/users/{id}/edit",
            get(users::edit_form).post(users::update),
        )
        .route("/dashboard/users/{id}/set-status", post(users::set_status))
        .route(
            "/dashboard/users/{id}/reset-password",
            post(users::reset_password),
        )
        .route("/dashboard/users/{id}/grant-app", post(users::grant_app))
        .route("/dashboard/users/{id}/revoke-app", post(users::revoke_app))
        .route("/dashboard/providers", get(providers::list))
        .route(
            "/dashboard/providers/new",
            get(providers::new_form).post(providers::create),
        )
        .route("/dashboard/providers/{id}", get(providers::detail))
        .route(
            "/dashboard/providers/{id}/edit",
            get(providers::edit_form).post(providers::update),
        )
        .route(
            "/dashboard/providers/{id}/toggle",
            post(providers::toggle_enabled),
        )
        .route("/dashboard/providers/{id}/keys/new", post(keys::create))
        .route(
            "/dashboard/providers/{id}/keys/{kid}/activate",
            post(keys::activate),
        )
        .route(
            "/dashboard/providers/{id}/keys/{kid}/revoke",
            post(keys::revoke),
        )
        .layer(middleware::from_fn_with_state(
            state,
            require_admin_middleware,
        ))
}
