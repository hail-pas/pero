use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;

use crate::cookie;
use crate::state::AppState;

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
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
