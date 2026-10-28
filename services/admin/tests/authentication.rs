use admin::{config::AppConfig, state::AppState};
use axum::{
    Router,
    http::{Request, StatusCode},
    routing::get,
};
use tower::ServiceExt;

const PRIVATE: &str = include_str!("../../../tests/fixtures/rsa-private.pem");
const PUBLIC: &str = include_str!("../../../tests/fixtures/rsa-public.pem");

fn config(issuer: &str) -> AppConfig {
    serde_json::from_value(serde_json::json!({"oauth2": {"issuer":issuer,"client_id":"client"},"cookie":{"domain":"example.test","path":"/"}})).unwrap()
}

#[tokio::test]
async fn unauthenticated_request_redirects_to_login() {
    let app = admin::router::build(AppState::new(config("http://127.0.0.1:1")));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["location"], "/login");
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|c| c.to_str().unwrap())
        .collect();
    assert_eq!(cookies.len(), 5);
    assert!(
        cookies
            .iter()
            .all(|cookie| cookie.contains("Domain=example.test") && cookie.contains("Max-Age=0"))
    );
}

fn sign(claims: &serde_json::Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test".into());
    if claims.get("scope").is_some() {
        header.typ = Some("at+jwt".into());
    }
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn signed_identity_requires_the_same_client_session_and_live_grant() {
    use std::sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    };
    let status = Arc::new(AtomicU16::new(200));
    let result_status = status.clone();
    let key = pero_utils::oauth::jwk::rsa_public_key_to_jwk(PUBLIC, "test", "RS256").unwrap();
    let mock = Router::new()
        .route(
            "/api/oauth2/jwks",
            get(move || {
                let key = key.clone();
                async move { axum::Json(serde_json::json!({"keys":[key]})) }
            }),
        )
        .route(
            "/api/oauth2/introspect",
            axum::routing::post(move || {
                let status = result_status.load(Ordering::SeqCst);
                async move {
                    (
                        if status == 401 {
                            StatusCode::OK
                        } else {
                            StatusCode::from_u16(status).unwrap()
                        },
                        axum::Json(if status == 401 {
                            serde_json::json!({"active":false})
                        } else {
                            serde_json::json!({"active":true,"sub":"user"})
                        }),
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let state = AppState::new(config(&issuer));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({"sub":"user","iss":issuer,"aud":"client","iat":now,"exp":now+60,"sid":"session"});
    let mut access_claims = claims.clone();
    access_claims["scope"] = "openid".into();
    access_claims["client_version"] = 0.into();
    access_claims["access_version"] = 0.into();
    let access = sign(&access_claims);
    let mut id_claims = claims.clone();
    id_claims["at_hash"] = pero_utils::oauth::jwt::oidc_hash(&access).into();
    let identity = sign(&id_claims);
    let jar = |id: String, at: String| {
        axum_extra::extract::CookieJar::new()
            .add(axum_extra::extract::cookie::Cookie::new("admin_it", id))
            .add(axum_extra::extract::cookie::Cookie::new("admin_at", at))
    };
    assert!(
        admin::middleware::authenticated_user(&state, &jar(identity.clone(), access.clone()))
            .await
            .unwrap()
            .is_some()
    );
    // Legacy ID tokens without at_hash still require signed matching audience and sid.
    assert!(
        admin::middleware::authenticated_user(&state, &jar(sign(&claims), access.clone()))
            .await
            .unwrap()
            .is_some()
    );
    for (field, value) in [
        ("aud", "other-client"),
        ("sid", "other-session"),
        ("sub", "other-user"),
    ] {
        let mut mixed = access_claims.clone();
        mixed[field] = value.into();
        assert!(
            admin::middleware::authenticated_user(&state, &jar(sign(&claims), sign(&mixed)))
                .await
                .unwrap()
                .is_none(),
            "{field}"
        );
    }
    let mut different_at = access_claims.clone();
    different_at["iat"] = (now - 1).into();
    assert!(
        admin::middleware::authenticated_user(&state, &jar(identity.clone(), sign(&different_at)))
            .await
            .unwrap()
            .is_none()
    );
    status.store(401, Ordering::SeqCst);
    assert!(
        admin::middleware::authenticated_user(&state, &jar(identity.clone(), access.clone()))
            .await
            .unwrap()
            .is_none()
    );
    status.store(503, Ordering::SeqCst);
    assert!(
        admin::middleware::authenticated_user(&state, &jar(identity.clone(), access.clone()))
            .await
            .is_err()
    );
    let response = admin::router::build(state.clone())
        .oneshot(
            Request::builder()
                .uri("/")
                .header("cookie", format!("admin_it={identity}; admin_at={access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(
        admin::middleware::authenticated_user(&state, &jar(format!("{identity}x"), access))
            .await
            .unwrap()
            .is_none()
    );
    task.abort();
}

#[tokio::test]
async fn logout_preserves_the_complete_registered_redirect() {
    let mut cfg = config("https://issuer.example.test/");
    cfg.oauth2.post_logout_redirect_uri = "https://client.example.test/bye?a=1&b=2".into();
    let (jar, csrf_token) = pero_api_axum::csrf::ensure_csrf(
        axum_extra::extract::CookieJar::new(),
        &admin::cookie::csrf_config(&cfg),
    );
    let response = admin::handler::logout::logout(
        axum::extract::State(AppState::new(cfg)),
        jar,
        axum::Form(admin::handler::logout::LogoutForm { csrf_token }),
    )
    .await;
    assert_eq!(
        response.headers()["location"],
        "https://issuer.example.test/oauth2/session/end?post_logout_redirect_uri=https%3A%2F%2Fclient.example.test%2Fbye%3Fa%3D1%26b%3D2"
    );
}

#[tokio::test]
async fn issuer_endpoints_preserve_prefix_without_double_slashes() {
    use axum::routing::post;
    let key = pero_utils::oauth::jwk::rsa_public_key_to_jwk(PUBLIC, "test", "RS256").unwrap();
    let mock = Router::new()
        .route(
            "/tenant/api/oauth2/token",
            post(|| async { axum::Json(serde_json::json!({"access_token":"test"})) }),
        )
        .route(
            "/tenant/api/oauth2/jwks",
            get(move || {
                let key = key.clone();
                async move { axum::Json(serde_json::json!({"keys":[key]})) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/tenant/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let state = AppState::new(config(&issuer));
    assert!(
        admin::oauth2::exchange_code(
            &state.http,
            &issuer,
            "client",
            "secret",
            "code",
            "https://example.test/cb",
            "verifier"
        )
        .await
        .is_ok()
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token =
        sign(&serde_json::json!({"iss":issuer,"sub":"user","aud":"client","iat":now,"exp":now+60}));
    assert!(
        admin::oauth2::verify_id_token(&state.jwks, &state.http, &issuer, "client", &token)
            .await
            .is_ok()
    );
    assert!(
        admin::oauth2::verify_id_token(
            &state.jwks,
            &state.http,
            issuer.trim_end_matches('/'),
            "client",
            &token
        )
        .await
        .is_err()
    );
    let response = admin::handler::home::home(
        axum::extract::State(state),
        axum_extra::extract::CookieJar::new(),
        admin::middleware::CurrentUser {
            sub: "user".into(),
            username: "test-user".into(),
            email: None,
            name: None,
            picture: None,
        },
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let base = issuer.trim_end_matches('/');
    assert_eq!(
        page["data"]["profile_url"],
        format!("{base}/account/profile")
    );
    assert_eq!(
        page["data"]["password_url"],
        format!("{base}/account/change-password")
    );
    task.abort();
}

#[tokio::test]
async fn logout_rejects_missing_forged_and_other_session_csrf_without_clearing_cookies() {
    use axum_extra::extract::{CookieJar, cookie::Cookie};
    let cfg = config("https://issuer.example.test");
    let (jar, token) = pero_api_axum::csrf::ensure_csrf(
        CookieJar::new().add(Cookie::new("admin_at", "session-one")),
        &admin::cookie::csrf_config(&cfg),
    );
    let app = admin::router::build(AppState::new(cfg));
    for (session, submitted, expected) in [
        ("session-one", "", StatusCode::FORBIDDEN),
        ("session-one", "forged", StatusCode::FORBIDDEN),
        ("session-two", token.as_str(), StatusCode::FORBIDDEN),
        ("session-one", token.as_str(), StatusCode::FOUND),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "cookie",
                        format!(
                            "admin_at={session}; admin_csrf={}",
                            jar.get("admin_csrf").unwrap().value()
                        ),
                    )
                    .body(axum::body::Body::from(format!("csrf_token={submitted}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            response.headers().contains_key("set-cookie"),
            expected == StatusCode::FOUND
        );
    }
}

#[test]
fn authentication_cookies_follow_each_tokens_remaining_lifetime() {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let response = admin::oauth2::TokenResponse {
        access_token: "access".into(),
        id_token: Some("identity".into()),
    };
    let jar = admin::cookie::set_auth_cookies(
        axum_extra::extract::CookieJar::new(),
        &response,
        &config("https://issuer.example.test"),
        now + 14400,
        now + 300,
    );
    for (name, lifetime) in [("admin_at", 14400), ("admin_it", 300)] {
        let remaining = jar.get(name).unwrap().max_age().unwrap().whole_seconds();
        assert!((lifetime - 1..=lifetime).contains(&remaining));
    }
}
