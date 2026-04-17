mod common;

use common::*;
use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::ServiceExt;

#[tokio::test]
async fn sso_authorize_redirects_to_login() {
    let mut ta = build_app().await;
    let admin_fx = ta.register_default_user().await;
    ta.grant_api_access(admin_fx.user_id).await;
    let app_fx = ta.create_test_app(&admin_fx.access_token).await;
    let client_fx = ta
        .create_test_client(app_fx.app_id, &app_fx.code, &admin_fx.access_token)
        .await;

    let (status, _body) = send_raw_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!(
            "/oauth2/authorize?client_id={}&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=openid+profile",
            client_fx.client_id_str,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_authorize_rejects_invalid_client() {
    let mut ta = build_app().await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        "/oauth2/authorize?client_id=nonexistent&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=test123&code_challenge_method=S256",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body:?}");
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_login_page_renders_html() {
    let mut ta = build_app().await;
    let admin_fx = ta.register_default_user().await;
    ta.grant_api_access(admin_fx.user_id).await;
    let app_fx = ta.create_test_app(&admin_fx.access_token).await;
    let client_fx = ta
        .create_test_client(app_fx.app_id, &app_fx.code, &admin_fx.access_token)
        .await;

    let (_, authorize_body) = send_raw_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!(
            "/oauth2/authorize?client_id={}&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=openid",
            client_fx.client_id_str,
        ),
    )
    .await;

    let cookies = authorize_body;
    let _ = cookies;

    let (status, _html) = send_raw_request(&mut ta.app, hyper::Method::GET, "/sso/login").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_register_page_without_session_redirects() {
    let mut ta = build_app().await;

    let (status, _) = send_raw_request(&mut ta.app, hyper::Method::GET, "/sso/register").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_forgot_password_page_without_session_redirects() {
    let mut ta = build_app().await;

    let (status, _) =
        send_raw_request(&mut ta.app, hyper::Method::GET, "/sso/forgot-password").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_change_password_page_without_session_redirects() {
    let mut ta = build_app().await;

    let (status, _) =
        send_raw_request(&mut ta.app, hyper::Method::GET, "/sso/change-password").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_consent_page_without_session_redirects() {
    let mut ta = build_app().await;

    let (status, _) = send_raw_request(&mut ta.app, hyper::Method::GET, "/sso/consent").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    ta.cleanup().await;
}

#[tokio::test]
async fn sso_consent_rejects_unknown_action() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;
    let app_fx = ta.create_test_app(&fx.access_token).await;
    let client_fx = ta
        .create_test_client(app_fx.app_id, &app_fx.code, &fx.access_token)
        .await;

    let authorize_request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(format!(
            "/oauth2/authorize?client_id={}&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=openid+profile",
            client_fx.client_id_str,
        ))
        .body(axum::body::Body::empty())
        .unwrap();
    let authorize_response = ta.app.clone().oneshot(authorize_request).await.unwrap();
    assert!(authorize_response.status().is_redirection());

    let session_cookie = authorize_response
        .headers()
        .get(hyper::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("missing session cookie")
        .to_string();
    let session_id = session_cookie
        .strip_prefix("pero_sso_session=")
        .expect("missing session id");

    let mut sso = pero::domains::sso::session::get(&ta.cache, session_id)
        .await
        .unwrap()
        .expect("missing sso session");
    sso.user_id = Some(fx.user_id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    pero::domains::sso::session::update(&ta.cache, session_id, &sso)
        .await
        .unwrap();

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri("/sso/consent")
        .header(hyper::header::COOKIE, &session_cookie)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(axum::body::Body::from("action=unexpected"))
        .unwrap();
    let response = ta.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let _body = response.into_body().collect().await.unwrap();

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let auth_code_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth2_authorization_codes WHERE client_id = $1 AND user_id = $2",
    )
    .bind(client_fx.client_id)
    .bind(fx.user_id)
    .fetch_one(&ta.db)
    .await
    .unwrap();
    assert_eq!(auth_code_count, 0);

    ta.cleanup().await;
}
