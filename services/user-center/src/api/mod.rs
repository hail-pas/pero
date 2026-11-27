pub mod account_sync;
mod client_auth;
pub mod health;
pub mod jwks;
pub mod providers;
pub mod tenant_management;
pub mod tenant_reconcile;
pub mod token;
pub mod token_management;
pub mod userinfo;

use axum::Router;
use axum::routing::{get, post};

pub fn routes() -> Router<crate::state::app::AppState> {
    Router::new()
        .route(
            "/tenants",
            get(tenant_management::list).post(tenant_management::create),
        )
        .route("/tenants/choices", get(tenant_management::choices))
        .route("/tenants/{id}", get(tenant_management::detail))
        .route("/tenants/{id}/members", get(tenant_management::members))
        .route(
            "/tenants/{id}/members/{user}",
            post(tenant_management::update_member),
        )
        .route(
            "/tenants/{id}/invitations",
            get(tenant_management::invitations).post(tenant_management::invite),
        )
        .route(
            "/tenants/{id}/invitations/{invitation}/revoke",
            post(tenant_management::revoke_invitation),
        )
        .route("/tenants/{id}/rename", post(tenant_management::rename))
        .route("/tenants/{id}/leave", post(tenant_management::leave))
        .route("/tenants/{id}/status", post(tenant_management::set_status))
        .route("/accounts/sync", post(account_sync::snapshot))
        .route("/accounts/sync/list", post(tenant_reconcile::accounts))
        .route("/tenants/sync", post(tenant_reconcile::tenant))
        .route("/tenants/list", post(tenant_reconcile::tenants))
        .route(
            "/tenants/membership/list",
            post(tenant_reconcile::memberships),
        )
        .route(
            "/tenants/membership/sync",
            post(tenant_reconcile::membership),
        )
        .route_layer(axum::middleware::from_fn(no_store))
        .route("/health", get(health::health))
        .route("/ready", get(health::ready))
        .route("/oauth2/token", post(token::token))
        .route("/oauth2/introspect", post(token_management::introspect))
        .route("/oauth2/revoke", post(token_management::revoke))
        .route("/oauth2/jwks", get(jwks::jwks))
        .route(
            "/oauth2/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route("/providers", get(providers::providers))
}

async fn no_store(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    let token = token.trim_start_matches(' ');
    (scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bearer_scheme_is_case_insensitive_and_requires_credentials() {
        for value in ["Bearer token", "bearer token", "bEaReR  token"] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
            assert_eq!(super::extract_bearer(&headers), Some("token"));
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            axum::http::header::AUTHORIZATION,
            "Bearer first".parse().unwrap(),
        );
        headers.append(
            axum::http::header::AUTHORIZATION,
            "Bearer second".parse().unwrap(),
        );
        assert_eq!(super::extract_bearer(&headers), None);
        for value in ["Basic token", "Bearer", "Bearer   "] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
            assert_eq!(super::extract_bearer(&headers), None);
        }
    }
}
