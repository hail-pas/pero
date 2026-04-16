use crate::shared::state::AppState;
use axum::Router;
use axum::http::header;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::normalize_path::NormalizePathLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::trace::TraceLayer;
use utoipa_swagger_ui::SwaggerUi;

pub fn build_router(state: AppState) -> Router {
    use axum::routing::{get, post};

    let public = Router::new()
        .route("/health", get(crate::routes::health::health))
        .route(
            "/auth/refresh",
            post(crate::domains::identity::routes::login::refresh),
        )
        .route(
            "/oauth2/token",
            post(crate::domains::oauth2::routes::token::token),
        )
        .route(
            "/oauth2/revoke",
            post(crate::domains::oauth2::routes::revoke::revoke),
        )
        .route(
            "/.well-known/openid-configuration",
            get(crate::domains::oidc::routes::discovery::discovery),
        )
        .route(
            "/oauth2/keys",
            get(crate::domains::oidc::routes::jwks::jwks),
        );

    let auth_only = Router::new()
        .route(
            "/auth/logout",
            post(crate::domains::identity::routes::login::logout),
        )
        .route(
            "/oauth2/authorize",
            get(crate::domains::oauth2::routes::authorize::authorize),
        )
        .route(
            "/oauth2/userinfo",
            get(crate::domains::oidc::routes::userinfo::userinfo),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::middleware::auth::auth_middleware,
        ));

    let authorized = Router::new()
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
        .route(
            "/api/users/{id}/attributes",
            get(crate::domains::identity::routes::user_attrs::list_attributes)
                .put(crate::domains::identity::routes::user_attrs::set_attributes),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::domains::abac::middleware::abac_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::middleware::auth::auth_middleware,
        ));

    let identity_public = Router::new()
        .route(
            "/api/identity/register",
            post(crate::domains::identity::routes::registration::register),
        )
        .route(
            "/api/identity/login",
            post(crate::domains::identity::routes::login::login),
        );

    let identity_authed = Router::new()
        .route(
            "/api/users/me",
            get(crate::domains::identity::routes::profile::get_me)
                .put(crate::domains::identity::routes::profile::update_me),
        )
        .route(
            "/api/identity/bind/{provider}",
            post(crate::domains::identity::routes::binding::bind),
        )
        .route(
            "/api/identity/unbind/{provider}",
            axum::routing::delete(crate::domains::identity::routes::binding::unbind),
        )
        .route(
            "/api/identity/password/change",
            axum::routing::put(crate::domains::identity::routes::password::change_password),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::middleware::auth::auth_middleware,
        ));

    let openapi = crate::docs::build_openapi(&state.config.docs);

    let x_request_id = axum::http::HeaderName::from_static("x-request-id");

    Router::new()
        .merge(public)
        .merge(auth_only)
        .merge(authorized)
        .merge(identity_public)
        .merge(identity_authed)
        .merge(SwaggerUi::new("/docs").url("/openapi.json", openapi))
        .with_state(state.clone())
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
        .layer({
            let burst = state.config.server.rate_limit_burst as usize;
            tower::layer::layer_fn(move |service| {
                crate::shared::middleware::rate_limit::RateLimit {
                    inner: service,
                    limiter: std::sync::Arc::new(tokio::sync::Semaphore::new(burst)),
                }
            })
        })
        // NormalizePathLayer: merge/trim trailing slashes
        .layer(NormalizePathLayer::trim_trailing_slash())
}
