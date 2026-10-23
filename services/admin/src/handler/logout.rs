use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;

use crate::cookie;
use crate::state::AppState;

#[derive(serde::Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<LogoutForm>,
) -> Response {
    if !pero_api_axum::csrf::verify_csrf(
        &jar,
        &form.csrf_token,
        &cookie::csrf_config(&state.config),
    ) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error":"invalid_csrf"})),
        )
            .into_response();
    }
    let id_token = jar
        .get("admin_it")
        .map(|c| c.value().to_owned())
        .unwrap_or_default();

    let jar = cookie::clear_auth_cookies(jar, &state.config);

    let issuer = &state.config.oauth2.issuer;
    let post_logout = &state.config.oauth2.post_logout_redirect_uri;
    let mut logout_url = pero_utils::oauth::url::issuer_endpoint(issuer, "oauth2/session/end");
    if !id_token.is_empty() {
        pero_utils::encode::append_query_param(&mut logout_url, "id_token_hint", &id_token);
    }
    pero_utils::encode::append_query_param(
        &mut logout_url,
        "post_logout_redirect_uri",
        post_logout,
    );

    (
        jar,
        (axum::http::StatusCode::FOUND, [("Location", logout_url)]),
    )
        .into_response()
}
