pub mod docs;
pub mod extractors;
pub mod health;
pub mod middleware;
pub mod response;

use crate::shared::constants::headers::X_REQUEST_ID;
use crate::shared::state::AppState;
use axum::Router;
use axum::http::header;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::normalize_path::NormalizePathLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::trace::TraceLayer;
use utoipa_swagger_ui::SwaggerUi;

pub fn build_router(state: AppState) -> Router {
    let public = build_public_routes(&state);
    let login_required = build_login_required_routes(&state);
    let abac_required = build_abac_required_routes(&state);
    let client_required = build_client_required_routes(&state);

    let openapi = crate::api::docs::build_openapi(&state.config.docs);

    let x_request_id = axum::http::HeaderName::from_static(X_REQUEST_ID);

    let cors = build_cors(&state.config.cors);

    Router::new()
        .merge(public)
        .merge(login_required)
        .merge(abac_required)
        .merge(client_required)
        .merge(SwaggerUi::new("/docs").url("/openapi.json", openapi))
        .with_state(state.clone())
        .layer(cors)
        // --- tower-http middleware stack (outermost = last applied to request) ---
        // TraceLayer: structured request/response tracing
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    tower_http::trace::DefaultMakeSpan::new()
                        .level(tracing::Level::INFO)
                        .include_headers(true),
                )
                .on_request(tower_http::trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(
                    tower_http::trace::DefaultOnResponse::new()
                        .level(tracing::Level::INFO)
                        .include_headers(true),
                )
                .on_failure(
                    tower_http::trace::DefaultOnFailure::new().level(tracing::Level::ERROR),
                ),
        )
        // PropagateRequestIdLayer: copy x-request-id from request to response
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        // SetRequestIdLayer: generate x-request-id if not present
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
        // SetSensitiveHeadersLayer: mask Authorization and Cookie headers in traces
        .layer(SetSensitiveHeadersLayer::new(vec![
            header::AUTHORIZATION,
            header::COOKIE,
        ]))
        // RequestBodyLimitLayer: reject oversized request bodies
        .layer(RequestBodyLimitLayer::new(
            state.config.server.request_body_limit_bytes,
        ))
        // CatchPanicLayer: convert panics into 500 responses
        .layer(CatchPanicLayer::new())
        // NormalizePathLayer: merge/trim trailing slashes
        .layer(NormalizePathLayer::trim_trailing_slash())
}

fn build_public_routes(state: &AppState) -> Router<AppState> {
    use axum::routing::{get, post};

    let unprotected = Router::new()
        .route("/health", get(crate::api::health::health))
        .route(
            "/.well-known/openid-configuration",
            get(crate::handler::oidc::discovery::discovery),
        )
        .route(
            "/oauth2/keys",
            get(crate::handler::oidc::jwks::jwks),
        )
        .route(
            "/oauth2/authorize",
            get(crate::handler::oauth2::authorize::authorize),
        )
        .route(
            "/sso/consent",
            get(crate::handler::sso::consent::consent_get)
                .post(crate::handler::sso::consent::consent_post),
        );

    let rate_limited = Router::new()
        .route(
            "/api/identity/register",
            post(crate::handler::identity::registration::register),
        )
        .route(
            "/api/identity/login",
            post(crate::handler::identity::login::login),
        )
        .route(
            "/auth/refresh",
            post(crate::handler::identity::login::refresh),
        )
        .route(
            "/oauth2/token",
            post(crate::handler::oauth2::token::token),
        )
        .route(
            "/oauth2/revoke",
            post(crate::handler::oauth2::revoke::revoke),
        )
        .route(
            "/sso/login",
            get(crate::handler::sso::login::login_get)
                .post(crate::handler::sso::login::login_post),
        )
        .route(
            "/sso/register",
            get(crate::handler::sso::register::register_get)
                .post(crate::handler::sso::register::register_post),
        )
        .route(
            "/sso/forgot-password",
            get(crate::handler::sso::forgot::forgot_get)
                .post(crate::handler::sso::forgot::forgot_post),
        )
        .route(
            "/sso/change-password",
            get(crate::handler::sso::change_password::change_password_get)
                .post(crate::handler::sso::change_password::change_password_post),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::rate_limit::rate_limit_middleware,
        ));

    unprotected.merge(rate_limited)
}

fn build_login_required_routes(state: &AppState) -> Router<AppState> {
    use axum::routing::{delete, get, post, put};

    Router::new()
        .route(
            "/api/users/me",
            get(crate::handler::identity::profile::get_me)
                .put(crate::handler::identity::profile::update_me),
        )
        .route(
            "/api/identity/password/change",
            put(crate::handler::identity::password::change_password),
        )
        .route(
            "/api/identity/unbind/{provider}",
            delete(crate::handler::identity::binding::unbind),
        )
        .route(
            "/api/identity/identities",
            get(crate::handler::identity::binding::list_identities),
        )
        .route(
            "/auth/logout",
            post(crate::handler::identity::login::logout),
        )
        .route(
            "/oauth2/userinfo",
            get(crate::handler::oidc::userinfo::userinfo),
        )
        .route(
            "/api/abac/evaluate",
            post(crate::handler::abac::evaluate::evaluate),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::auth::auth_middleware,
        ))
}

fn build_abac_required_routes(state: &AppState) -> Router<AppState> {
    use axum::routing::{delete, get, post};

    Router::new()
        .route(
            "/api/users",
            post(crate::handler::identity::registration::create_user)
                .get(crate::handler::identity::profile::list_users),
        )
        .route(
            "/api/users/{id}",
            get(crate::handler::identity::profile::get_user)
                .put(crate::handler::identity::profile::update_user)
                .delete(crate::handler::identity::profile::delete_user),
        )
        .route(
            "/api/users/{id}/attributes",
            get(crate::handler::identity::user_attrs::list_attributes)
                .put(crate::handler::identity::user_attrs::set_attributes),
        )
        .route(
            "/api/users/{id}/attributes/{key}",
            delete(crate::handler::identity::user_attrs::delete_attribute),
        )
        .route(
            "/api/apps",
            post(crate::handler::app::crud::create_app)
                .get(crate::handler::app::crud::list_apps),
        )
        .route(
            "/api/apps/{id}",
            get(crate::handler::app::crud::get_app)
                .put(crate::handler::app::crud::update_app)
                .delete(crate::handler::app::crud::delete_app),
        )
        .route(
            "/api/oauth2/clients",
            post(crate::handler::oauth2::client_management::create_client)
                .get(crate::handler::oauth2::client_management::list_clients),
        )
        .route(
            "/api/oauth2/clients/{id}",
            get(crate::handler::oauth2::client_management::get_client)
                .put(crate::handler::oauth2::client_management::update_client)
                .delete(crate::handler::oauth2::client_management::delete_client),
        )
        .route(
            "/api/policies",
            post(crate::handler::abac::policies::create_policy)
                .get(crate::handler::abac::policies::list_policies),
        )
        .route(
            "/api/policies/{id}",
            get(crate::handler::abac::policies::get_policy)
                .put(crate::handler::abac::policies::update_policy)
                .delete(crate::handler::abac::policies::delete_policy),
        )
        .route(
            "/api/users/{user_id}/policies",
            get(crate::handler::abac::policies::list_user_policies),
        )
        .route(
            "/api/users/{user_id}/policies/{policy_id}",
            post(crate::handler::abac::policies::assign_policy)
                .delete(crate::handler::abac::policies::unassign_policy),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::abac::abac_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::auth::auth_middleware,
        ))
}

fn build_client_required_routes(state: &AppState) -> Router<AppState> {
    use axum::routing::{get, post};

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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::client_auth::client_credentials_middleware,
        ))
}

fn build_cors(cfg: &crate::config::CorsConfig) -> CorsLayer {
    use axum::http::{HeaderName, Method};
    let mut layer = CorsLayer::new();

    if cfg.allow_origins.is_empty() {
        tracing::warn!("CORS allow_origins is empty, denying all cross-origin requests");
    } else if cfg.allow_origins.iter().any(|o| o == "*") {
        layer = layer.allow_origin(Any);
    } else {
        let origins: Vec<_> = cfg
            .allow_origins
            .iter()
            .filter_map(|o| {
                let parsed = o.parse().ok();
                if parsed.is_none() {
                    tracing::warn!(origin = %o, "invalid CORS origin, ignoring");
                }
                parsed
            })
            .collect();
        if !origins.is_empty() {
            layer = layer.allow_origin(origins);
        }
    }

    if cfg.allow_methods.is_empty() {
        tracing::warn!("CORS allow_methods is empty, using default methods");
        layer = layer.allow_methods(Any);
    } else {
        let methods: Vec<_> = cfg
            .allow_methods
            .iter()
            .filter_map(|m| {
                let parsed = m.parse::<Method>().ok();
                if parsed.is_none() {
                    tracing::warn!(method = %m, "invalid CORS method, ignoring");
                }
                parsed
            })
            .collect();
        layer = layer.allow_methods(methods);
    }

    if cfg.allow_headers.is_empty() {
        tracing::warn!("CORS allow_headers is empty, using default headers");
        layer = layer.allow_headers(Any);
    } else {
        let headers: Vec<_> = cfg
            .allow_headers
            .iter()
            .filter_map(|h| {
                let parsed = h.parse::<HeaderName>().ok();
                if parsed.is_none() {
                    tracing::warn!(header = %h, "invalid CORS header, ignoring");
                }
                parsed
            })
            .collect();
        layer = layer.allow_headers(headers);
    }

    layer
}
