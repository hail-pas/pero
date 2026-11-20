pub mod account_sync;
mod client_auth;
pub mod health;
pub mod jwks;
pub mod providers;
pub mod tenant_management;
pub mod tenant_membership;
pub mod tenant_reconcile;
pub mod token;
pub mod token_management;
pub mod userinfo;

use axum::Router;
use axum::routing::{get, post};

pub fn routes() -> Router<crate::state::app::AppState> {
    Router::new()
        .route("/accounts/sync", post(account_sync::snapshot))
        .route(
            "/tenants",
            get(tenant_management::list).post(tenant_management::create),
        )
        .route("/tenants/{id}", get(tenant_management::detail))
        .route("/tenants/{id}/members", get(tenant_management::members))
        .route(
            "/tenants/{id}/members/{user}",
            post(tenant_management::update_member),
        )
        .route("/tenants/{id}/invitations", post(tenant_management::invite))
        .route("/tenants/{id}/rename", post(tenant_management::rename))
        .route("/tenants/{id}/leave", post(tenant_management::leave))
        .route("/tenants/{id}/toggle", post(tenant_management::toggle))
        .route("/tenants/{id}/delete", post(tenant_management::delete))
        .route("/accounts/sync/list", post(tenant_reconcile::accounts))
        .route(
            "/tenants/membership/list",
            post(tenant_reconcile::memberships),
        )
        .route(
            "/tenants/membership/sync",
            post(tenant_membership::snapshot),
        )
        .route("/health", get(health::health))
        .route("/ready", get(health::ready))
        .route("/oauth2/token", post(token::token))
        .route("/oauth2/introspect", post(token_management::introspect))
        .route("/oauth2/revoke", post(token_management::revoke))
        .route("/oauth2/jwks", get(jwks::jwks))
        .route("/oauth2/userinfo", get(userinfo::userinfo))
        .route("/providers", get(providers::providers))
}
