use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;

use crate::middleware::CurrentUser;
use crate::state::AppState;

pub async fn home(State(state): State<AppState>, jar: CookieJar, user: CurrentUser) -> Response {
    let (jar, csrf_token) =
        pero_api_axum::csrf::ensure_csrf(jar, &crate::cookie::csrf_config(&state.config));
    let issuer = &state.config.oauth2.issuer;
    let template = crate::handler::dto::AdminHomeView {
        csrf_token,
        username: user.username.clone(),
        email: user.email.clone().unwrap_or_default(),
        picture: user.picture.clone().unwrap_or_default(),
        profile_url: pero_utils::oauth::url::issuer_endpoint(issuer, "account/profile"),
        password_url: pero_utils::oauth::url::issuer_endpoint(issuer, "account/change-password"),
        issuer: issuer.clone(),
    };
    (jar, pero_api_axum::form::view("AdminHomeView", template)).into_response()
}
