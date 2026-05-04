use crate::domain::abac::resource::{AbacContextExt, Action, Resource};
use crate::shared::state::AppState;
use axum::routing::{delete, get, post, put};
use axum::Router;

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/apps",
            post(crate::handler::app::crud::create_app).abac_context(Resource::App, Action::Create),
        )
        .route(
            "/api/apps",
            get(crate::handler::app::crud::list_apps).abac_context(Resource::App, Action::List),
        )
        .route(
            "/api/apps/{id}",
            get(crate::handler::app::crud::get_app).abac_context(Resource::App, Action::Read),
        )
        .route(
            "/api/apps/{id}",
            put(crate::handler::app::crud::update_app).abac_context(Resource::App, Action::Update),
        )
        .route(
            "/api/apps/{id}",
            delete(crate::handler::app::crud::delete_app)
                .abac_context(Resource::App, Action::Delete),
        )
}
