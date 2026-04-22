use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::ServiceExt;

pub async fn send_request(
    app: &mut Router,
    method: hyper::Method,
    uri: &str,
    body: Option<serde_json::Value>,
    auth_token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = hyper::Request::builder().method(method).uri(uri);

    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(token) = auth_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }

    let request = if let Some(body) = body {
        builder
            .body(axum::body::Body::from(
                serde_json::to_string(&body).unwrap(),
            ))
            .unwrap()
    } else {
        builder.body(axum::body::Body::empty()).unwrap()
    };

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let body_json = if body_str.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&body_str).unwrap_or_else(|e| {
            panic!("Failed to parse response body as JSON: {e}\nBody: {body_str}")
        })
    };
    (status, body_json)
}

pub async fn send_basic_auth_request(
    app: &mut Router,
    method: hyper::Method,
    uri: &str,
    body: Option<serde_json::Value>,
    client_id: &str,
    client_secret: &str,
) -> (StatusCode, serde_json::Value) {
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"));
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Basic {credentials}"));

    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }

    let request = if let Some(body) = body {
        builder
            .body(axum::body::Body::from(
                serde_json::to_string(&body).unwrap(),
            ))
            .unwrap()
    } else {
        builder.body(axum::body::Body::empty()).unwrap()
    };

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let body_json = if body_str.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&body_str).unwrap_or_else(|e| {
            panic!("Failed to parse response body as JSON: {e}\nBody: {body_str}")
        })
    };
    (status, body_json)
}

pub async fn send_form_request(
    app: &mut Router,
    method: hyper::Method,
    uri: &str,
    form: &[(&str, String)],
) -> (StatusCode, serde_json::Value) {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().map(|(k, v)| (*k, v.as_str())))
        .finish();

    let request = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(encoded))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let body_json = if body_str.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&body_str).unwrap_or_else(|e| {
            panic!("Failed to parse response body as JSON: {e}\nBody: {body_str}")
        })
    };
    (status, body_json)
}

pub async fn send_raw_request(
    app: &mut Router,
    method: hyper::Method,
    uri: &str,
) -> (StatusCode, String) {
    let request = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    (status, body_str)
}
