use crate::domain::abac::resource::{AbacContextExt, Action, Resource};
use crate::shared::state::AppState;
use axum::Router;
use axum::routing::{delete, get, post, put};

pub fn login_required_routes() -> Router<AppState> {
    Router::new().route(
        "/api/abac/evaluate",
        post(crate::handler::abac::evaluate::evaluate),
    )
}

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/policies",
            post(crate::handler::abac::policies::create_policy)
                .abac_context(Resource::Policy, Action::Create),
        )
        .route(
            "/api/policies",
            get(crate::handler::abac::policies::list_policies)
                .abac_context(Resource::Policy, Action::List),
        )
        .route(
            "/api/policies/{id}",
            get(crate::handler::abac::policies::get_policy)
                .abac_context(Resource::Policy, Action::Read),
        )
        .route(
            "/api/policies/{id}",
            put(crate::handler::abac::policies::update_policy)
                .abac_context(Resource::Policy, Action::Update),
        )
        .route(
            "/api/policies/{id}",
            delete(crate::handler::abac::policies::delete_policy)
                .abac_context(Resource::Policy, Action::Delete),
        )
        .route(
            "/api/users/{user_id}/policies",
            get(crate::handler::abac::policies::list_user_policies)
                .abac_context(Resource::Policy, Action::List),
        )
        .route(
            "/api/users/{user_id}/policies/{policy_id}",
            post(crate::handler::abac::policies::assign_policy)
                .abac_context(Resource::Policy, Action::Assign),
        )
        .route(
            "/api/users/{user_id}/policies/{policy_id}",
            delete(crate::handler::abac::policies::unassign_policy)
                .abac_context(Resource::Policy, Action::Unassign),
        )
}

pub fn client_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/client/policies",
            post(crate::handler::abac::client_policies::create_policy)
                .get(crate::handler::abac::client_policies::list_policies),
        )
        .route(
            "/api/client/policies/{id}",
            get(crate::handler::abac::client_policies::get_policy)
                .put(crate::handler::abac::client_policies::update_policy)
                .delete(crate::handler::abac::client_policies::delete_policy),
        )
        .route(
            "/api/client/users/{user_id}/policies",
            get(crate::handler::abac::client_policies::list_user_policies),
        )
        .route(
            "/api/client/users/{user_id}/policies/{policy_id}",
            post(crate::handler::abac::client_policies::assign_policy)
                .delete(crate::handler::abac::client_policies::unassign_policy),
        )
}
