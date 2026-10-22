use axum::http::{HeaderName, HeaderValue, Method};
use pero_config::blocks::{CorsConfig, HttpMethod};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::headers;

const WILDCARD_ORIGIN: &str = "*";
const REQUIRED_EXPOSE_HEADERS: &[&str] = &[
    headers::X_REQUEST_ID,
    headers::SERVER_TIMING,
    headers::X_PROCESS_TIME_MS,
];

fn convert_method(method: &HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
        HttpMethod::Options => Method::OPTIONS,
        HttpMethod::Head => Method::HEAD,
    }
}

pub fn cors_layer(config: &CorsConfig) -> CorsLayer {
    let max_age = config
        .max_age_secs
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(3600));

    let mut layer = CorsLayer::new()
        .allow_origin(allow_origin(&config.allow_origins))
        .allow_methods(allow_methods(&config.allow_methods))
        .allow_headers(header_names(&config.allow_headers))
        .expose_headers(expose_headers(&config.expose_headers))
        .max_age(max_age);

    if config.allow_credentials {
        layer = layer.allow_credentials(true);
    }

    layer
}

fn allow_origin(origins: &[String]) -> AllowOrigin {
    if origins.is_empty()
        || origins
            .iter()
            .any(|origin| origin.trim() == WILDCARD_ORIGIN)
    {
        return Any.into();
    }

    AllowOrigin::list(header_values(origins))
}

fn allow_methods(methods: &[HttpMethod]) -> Vec<Method> {
    methods.iter().map(convert_method).collect()
}

fn expose_headers(configured: &[String]) -> Vec<HeaderName> {
    let mut headers = header_names(configured);

    for required in REQUIRED_EXPOSE_HEADERS {
        if let Ok(required) = required.parse::<HeaderName>()
            && !headers.contains(&required)
        {
            headers.push(required);
        }
    }

    headers
}

fn header_names(values: &[String]) -> Vec<HeaderName> {
    values
        .iter()
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn header_values(values: &[String]) -> Vec<HeaderValue> {
    values
        .iter()
        .filter_map(|value| value.parse().ok())
        .collect()
}
