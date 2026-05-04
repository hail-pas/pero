use crate::shared::state::AppState;
use axum::Router;
use axum::routing::{get, post};

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/apps",
            post(crate::handler::app::crud::create_app).get(crate::handler::app::crud::list_apps),
        )
        .route(
            "/api/apps/{id}",
            get(crate::handler::app::crud::get_app)
                .put(crate::handler::app::crud::update_app)
                .delete(crate::handler::app::crud::delete_app),
        )
}
