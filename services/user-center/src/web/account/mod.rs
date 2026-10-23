pub mod change_password;
pub mod contact;
pub mod dto;
pub mod login;
pub mod logout;
pub mod profile;
pub mod security;

use axum::Router;
use axum::routing::{get, post};

use crate::state::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/account/sessions", get(security::sessions))
        .route("/account/sessions/revoke", post(security::revoke_sessions))
        .route("/account/activity", get(security::activity))
        .route("/account/authorizations", get(security::authorizations))
        .route(
            "/account/authorizations/{id}/revoke",
            post(security::revoke_authorization),
        )
        .route("/account/identities", get(security::identities))
        .route("/account/identities/{id}/unlink", post(security::unlink))
        .route("/account/identities/{provider}/link", post(security::link))
        .route("/account/login", get(login::get).post(login::post))
        .route("/account/profile", get(profile::get).post(profile::post))
        .route(
            "/account/change-password",
            get(change_password::get).post(change_password::post),
        )
        .route("/account/logout", post(logout::logout))
        .route(
            "/account/profile/send-verify-email",
            post(contact::send_verify_email),
        )
        .route(
            "/account/profile/send-verify-phone",
            post(contact::send_verify_phone),
        )
        .route("/account/profile/change-email", post(contact::change_email))
        .route("/account/profile/change-phone", post(contact::change_phone))
        .route(
            "/account/profile/verify-contact",
            get(contact::verify_contact_get).post(contact::verify_contact),
        )
        .route(
            "/account/profile/cancel-contact",
            post(contact::cancel_contact),
        )
}
