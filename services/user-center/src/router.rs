use axum::Router;
use axum::routing::get;
use pero_api_axum::middleware::{
    client_ip_layer, cors_layer, process_time_layer, propagate_request_id_layer,
    set_request_id_layer, tracing_layer,
};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;

use crate::api;
use crate::state::app::AppState;
use crate::web;

pub fn build(state: AppState) -> Router {
    let config = &state.config;

    let cors = cors_layer(&config.server.cors);
    let tracing = tracing_layer(config.log.clone());
    let process_time = process_time_layer();
    let set_req_id = set_request_id_layer();
    let propagate_req_id = propagate_request_id_layer();
    let body_limit = RequestBodyLimitLayer::new(config.server.request_body_limit_bytes);
    let client_ip = client_ip_layer(
        config.server.trusted_proxies.clone(),
        config.server.client_ip_header,
    );
    let static_url = config.askama.static_url_prefix.clone();
    let static_dir = config.askama.static_dir.clone();

    Router::new()
        .nest("/api", api::routes())
        .merge(web::routes(state.clone()))
        .route("/health", get(api::health::health))
        .route(
            &format!("{static_url}/js/i18n.js"),
            get(|| async {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "application/javascript; charset=utf-8",
                    )],
                    include_str!(concat!(env!("OUT_DIR"), "/i18n.js")),
                )
            }),
        )
        .nest_service(&static_url, ServeDir::new(static_dir))
        .fallback(web::not_found)
        .layer(axum::middleware::from_fn(
            pero_api_axum::headers::security_headers,
        ))
        .layer(tracing)
        .layer(cors)
        .layer(propagate_req_id)
        .layer(set_req_id)
        .layer(body_limit)
        .layer(process_time)
        .layer(client_ip)
        .with_state(state)
}
