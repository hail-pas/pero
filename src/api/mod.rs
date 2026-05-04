pub mod docs;
pub mod extractors;
pub mod health;
pub mod middleware;
pub mod response;
pub mod routes;

use std::time::Duration;

use crate::domain::abac::models::RouteScope;

use crate::infra::http::error::ErrorInfo;
use crate::shared::constants::headers::{X_PROCESS_TIME, X_REQUEST_ID};
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
use tracing::Span;
use utoipa_swagger_ui::SwaggerUi;

#[derive(Clone)]
struct OnResponseLog;

impl<B> tower_http::trace::OnResponse<B> for OnResponseLog {
    fn on_response(self, response: &axum::http::Response<B>, latency: Duration, span: &Span) {
        let status = response.status();
        let ms = latency.as_millis();
        let info = response.extensions().get::<ErrorInfo>();

        if status.is_server_error() {
            match info {
                Some(i) => {
                    tracing::error!(parent: span, status = %status, latency = ms, code = i.code, message = %i.message)
                }
                None => tracing::error!(parent: span, status = %status, latency = ms),
            }
        } else if status.is_client_error() {
            match info {
                Some(i) => {
                    tracing::warn!(parent: span, status = %status, latency = ms, code = i.code, message = %i.message)
                }
                None => tracing::warn!(parent: span, status = %status, latency = ms),
            }
        } else {
            tracing::info!(parent: span, status = %status, latency = ms);
        }
    }
}

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
        .nest_service("/static", tower_http::services::ServeDir::new("ui/static"))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::shared::i18n::locale_middleware,
        ))
        .layer(cors)
        // --- tower-http middleware stack (outermost = last applied to request) ---
        // TraceLayer: structured request/response tracing
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::extract::Request| {
                    if request.method() == axum::http::Method::OPTIONS {
                        tracing::trace_span!("request")
                    } else {
                        tracing::info_span!(
                            "request",
                            method = %request.method(),
                            path = %request.uri().path(),
                        )
                    }
                })
                .on_request(tower_http::trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(OnResponseLog)
                .on_failure(
                    tower_http::trace::DefaultOnFailure::new().level(tracing::Level::ERROR),
                ),
        )
        // PropagateRequestIdLayer: copy x-request-id from request to response
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        // ResponseTimeLayer: measure request processing time and set x-process-time header
        .layer(axum::middleware::from_fn(
            crate::api::middleware::response_time::response_time_middleware,
        ))
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
    let unprotected = Router::new()
        .route("/health", axum::routing::get(crate::api::health::health))
        .merge(crate::api::routes::oauth::public_routes())
        .merge(crate::api::routes::social::public_routes())
        .route(
            "/sso/consent",
            axum::routing::get(crate::handler::sso::consent::consent_get)
                .post(crate::handler::sso::consent::consent_post),
        );

    let rate_limited = crate::api::routes::identity::public_routes()
        .merge(Router::new().route(
            "/oauth2/token",
            axum::routing::post(crate::handler::oauth2::token::token),
        ))
        .merge(Router::new().route(
            "/oauth2/revoke",
            axum::routing::post(crate::handler::oauth2::revoke::revoke),
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::rate_limit::rate_limit_middleware,
        ));

    let account = crate::api::routes::identity::account_routes()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::account_session::account_session_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::rate_limit::rate_limit_middleware,
        ));

    unprotected.merge(rate_limited).merge(account)
}

fn build_login_required_routes(state: &AppState) -> Router<AppState> {
    crate::api::routes::identity::login_required_routes()
        .merge(crate::api::routes::oauth::login_required_routes())
        .merge(crate::api::routes::abac::login_required_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::auth::auth_middleware,
        ))
}

fn build_abac_required_routes(state: &AppState) -> Router<AppState> {
    crate::api::routes::identity::admin_routes()
        .merge(crate::api::routes::app::admin_routes())
        .merge(crate::api::routes::oauth::admin_routes())
        .merge(crate::api::routes::abac::admin_routes())
        .merge(crate::api::routes::social::admin_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::abac::abac_middleware,
        ))
        .layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                req.extensions_mut().insert(RouteScope::Admin);
                next.run(req).await
            },
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::middleware::auth::auth_middleware,
        ))
}

fn build_client_required_routes(state: &AppState) -> Router<AppState> {
    crate::api::routes::abac::client_routes().layer(axum::middleware::from_fn_with_state(
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

    layer = layer.expose_headers([
        axum::http::HeaderName::from_static(X_REQUEST_ID),
        axum::http::HeaderName::from_static(X_PROCESS_TIME),
    ]);

    layer
}
