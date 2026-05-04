use crate::shared::state::AppState;
use axum::Router;
use axum::routing::{delete, get, post, put};

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/api/apps", post(crate::handler::app::crud::create_app))
        .route("/api/apps", get(crate::handler::app::crud::list_apps))
        .route("/api/apps/{id}", get(crate::handler::app::crud::get_app))
        .route("/api/apps/{id}", put(crate::handler::app::crud::update_app))
        .route(
            "/api/apps/{id}",
            delete(crate::handler::app::crud::delete_app),
        )
}
