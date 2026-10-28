pub mod consent;
pub mod dto;
pub mod forgot_password;
pub mod login;
pub mod register;
pub mod reset_password;
pub mod social;
pub mod utility;

use axum::Router;
use axum::routing::get;

use crate::state::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sso/select-account",
            get(crate::web::oauth2::select_account::get)
                .post(crate::web::oauth2::select_account::post),
        )
        .route("/sso/login", get(login::get).post(login::post))
        .route("/sso/register", get(register::get).post(register::post))
        .route(
            "/sso/forgot-password",
            get(forgot_password::get_forgot).post(forgot_password::post_forgot),
        )
        .route(
            "/sso/reset-password",
            get(reset_password::get_reset).post(reset_password::post_reset),
        )
        .route("/sso/consent", get(consent::get).post(consent::post))
        .route("/sso/error", get(utility::error_page))
        .route(
            "/sso/social/link",
            get(social::link_get).post(social::link_post),
        )
}

pub fn social_routes() -> Router<AppState> {
    Router::new()
        .route("/sso/social/{provider}/login", get(social::login))
        .route("/sso/social/{provider}/callback", get(social::callback))
}
