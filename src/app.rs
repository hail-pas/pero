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
    use axum::routing::{delete, get, post};

    // ====================================================================
    // ── Public: no authentication required ──────────────────────────────
    // ====================================================================
    let public = Router::new()
        .route("/health", get(crate::routes::health::health))
        // identity
        .route(
            "/api/identity/register",
            post(crate::domains::identity::routes::registration::register),
        )
        .route(
            "/api/identity/login",
            post(crate::domains::identity::routes::login::login),
        )
        .route(
            "/auth/refresh",
            post(crate::domains::identity::routes::login::refresh),
        )
        // oauth2 / oidc (validate credentials internally)
        .route(
            "/oauth2/token",
            post(crate::domains::oauth2::routes::token::token),
        )
        .route(
            "/oauth2/revoke",
            post(crate::domains::oauth2::routes::revoke::revoke),
        )
        .route(
            "/oauth2/authorize",
            get(crate::domains::oauth2::routes::authorize::authorize),
        )
        .route(
            "/.well-known/openid-configuration",
            get(crate::domains::oidc::routes::discovery::discovery),
        )
        .route(
            "/oauth2/keys",
            get(crate::domains::oidc::routes::jwks::jwks),
        )
        // sso pages
        .route(
            "/sso/login",
            get(crate::domains::sso::routes::login::login_get)
                .post(crate::domains::sso::routes::login::login_post),
        )
        .route(
            "/sso/register",
            get(crate::domains::sso::routes::register::register_get)
                .post(crate::domains::sso::routes::register::register_post),
        )
        .route(
            "/sso/consent",
            get(crate::domains::sso::routes::consent::consent_get)
                .post(crate::domains::sso::routes::consent::consent_post),
        )
        .route(
            "/sso/forgot-password",
            get(crate::domains::sso::routes::forgot::forgot_get)
                .post(crate::domains::sso::routes::forgot::forgot_post),
        )
        .route(
            "/sso/change-password",
            get(crate::domains::sso::routes::change_password::change_password_get)
                .post(crate::domains::sso::routes::change_password::change_password_post),
        );

    // ====================================================================
    // ── Login required: bearer token, no ABAC check ────────────────────
    // ====================================================================
    let login_required = Router::new()
        // identity — self-service
        .route(
            "/api/users/me",
            get(crate::domains::identity::routes::profile::get_me)
                .put(crate::domains::identity::routes::profile::update_me),
        )
        .route(
            "/api/identity/password/change",
            axum::routing::put(crate::domains::identity::routes::password::change_password),
        )
        .route(
            "/api/identity/unbind/{provider}",
            delete(crate::domains::identity::routes::binding::unbind),
        )
        .route(
            "/api/identity/identities",
            get(crate::domains::identity::routes::binding::list_identities),
        )
        // auth
        .route(
            "/auth/logout",
            post(crate::domains::identity::routes::login::logout),
        )
        // oidc
        .route(
            "/oauth2/userinfo",
            get(crate::domains::oidc::routes::userinfo::userinfo),
        )
        // abac evaluate
        .route(
            "/api/abac/evaluate",
            post(crate::domains::abac::routes::evaluate::evaluate),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::middleware::auth::auth_middleware,
        ));

    // ====================================================================
    // ── ABAC required: bearer token + policy check ──────────────────────
    // ====================================================================
    let abac_required = Router::new()
        // users (admin CRUD)
        .route(
            "/api/users",
            post(crate::domains::identity::routes::registration::create_user)
                .get(crate::domains::identity::routes::profile::list_users),
        )
        .route(
            "/api/users/{id}",
            get(crate::domains::identity::routes::profile::get_user)
                .put(crate::domains::identity::routes::profile::update_user)
                .delete(crate::domains::identity::routes::profile::delete_user),
        )
        .route(
            "/api/users/{id}/attributes",
            get(crate::domains::identity::routes::user_attrs::list_attributes)
                .put(crate::domains::identity::routes::user_attrs::set_attributes),
        )
        .route(
            "/api/users/{id}/attributes/{key}",
            delete(crate::domains::identity::routes::user_attrs::delete_attribute),
        )
        // apps
        .route(
            "/api/apps",
            post(crate::domains::app::routes::crud::create_app)
                .get(crate::domains::app::routes::crud::list_apps),
        )
        .route(
            "/api/apps/{id}",
            get(crate::domains::app::routes::crud::get_app)
                .put(crate::domains::app::routes::crud::update_app)
                .delete(crate::domains::app::routes::crud::delete_app),
        )
        // oauth2 clients
        .route(
            "/api/oauth2/clients",
            post(crate::domains::oauth2::routes::client_management::create_client)
                .get(crate::domains::oauth2::routes::client_management::list_clients),
        )
        .route(
            "/api/oauth2/clients/{id}",
            get(crate::domains::oauth2::routes::client_management::get_client)
                .put(crate::domains::oauth2::routes::client_management::update_client)
                .delete(crate::domains::oauth2::routes::client_management::delete_client),
        )
        // policies
        .route(
            "/api/policies",
            post(crate::domains::abac::routes::policies::create_policy)
                .get(crate::domains::abac::routes::policies::list_policies),
        )
        .route(
            "/api/policies/{id}",
            get(crate::domains::abac::routes::policies::get_policy)
                .put(crate::domains::abac::routes::policies::update_policy)
                .delete(crate::domains::abac::routes::policies::delete_policy),
        )
        .route(
            "/api/users/{user_id}/policies",
            get(crate::domains::abac::routes::policies::list_user_policies),
        )
        .route(
            "/api/users/{user_id}/policies/{policy_id}",
            post(crate::domains::abac::routes::policies::assign_policy)
                .delete(crate::domains::abac::routes::policies::unassign_policy),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::domains::abac::middleware::abac_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::middleware::auth::auth_middleware,
        ));

    // ====================================================================
    // ── Client credentials required: oauth2 client_auth ─────────────────
    // ====================================================================
    let client_required = Router::new()
        .route(
            "/api/client/policies",
            post(crate::domains::abac::routes::client_policies::create_policy)
                .get(crate::domains::abac::routes::client_policies::list_policies),
        )
        .route(
            "/api/client/policies/{id}",
            get(crate::domains::abac::routes::client_policies::get_policy)
                .put(crate::domains::abac::routes::client_policies::update_policy)
                .delete(crate::domains::abac::routes::client_policies::delete_policy),
        )
        .route(
            "/api/client/users/{user_id}/policies",
            get(crate::domains::abac::routes::client_policies::list_user_policies),
        )
        .route(
            "/api/client/users/{user_id}/policies/{policy_id}",
            post(crate::domains::abac::routes::client_policies::assign_policy)
                .delete(crate::domains::abac::routes::client_policies::unassign_policy),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::middleware::client_auth::client_credentials_middleware,
        ));

    let openapi = crate::docs::build_openapi(&state.config.docs);

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
