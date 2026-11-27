pub mod account;
pub mod dashboard;
pub mod error;
pub mod home;
pub mod login_flow;
pub mod navigation;
pub mod oauth2;
pub mod open;
pub mod security;
pub mod security_gate;
pub mod session;
pub mod sso;
pub mod util;

use axum::Router;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;

async fn notification_language(request: Request, next: Next) -> Response {
    use crate::service::notify::{Locale, NOTIFICATION_LOCALE};

    let headers = request.headers();
    let cookie_language = || {
        CookieJar::from_headers(headers)
            .get("pero_lang")
            .and_then(|cookie| Locale::from_tag(cookie.value()))
    };
    let requested_language = || {
        Locale::negotiate(
            headers
                .get_all(axum::http::header::ACCEPT_LANGUAGE)
                .iter()
                .filter_map(|value| value.to_str().ok()),
        )
    };
    let language = if pero_api_axum::spa::is_navigation(&request) {
        cookie_language().or_else(requested_language)
    } else {
        requested_language().or_else(cookie_language)
    };
    NOTIFICATION_LOCALE.scope(language, next.run(request)).await
}

pub fn routes(state: crate::state::app::AppState) -> Router<crate::state::app::AppState> {
    let directory = state.config.frontend.static_dir.clone();
    let pages = Router::new()
        .route("/", axum::routing::get(home::home))
        .merge(sso::routes().layer(middleware::from_fn(notification_language)))
        .merge(account::routes().layer(middleware::from_fn(notification_language)))
        .merge(dashboard::routes(state.clone()))
        .route_layer(axum::middleware::from_fn(move |req, next| {
            let directory = directory.clone();
            async move { pero_api_axum::spa::serve_page(req, next, directory).await }
        }));

    Router::new()
        .merge(pages)
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(open::openid_configuration),
        )
        .merge(oauth2::routes())
        .merge(sso::social_routes().layer(middleware::from_fn(notification_language)))
        .layer(axum::middleware::from_fn_with_state(
            state,
            security_gate::gate,
        ))
}

pub async fn not_found() -> Response {
    let tpl = sso::dto::ErrorView {
        code: "404".to_owned(),
    };
    (
        axum::http::StatusCode::NOT_FOUND,
        pero_api_axum::form::view("ErrorView", tpl),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::notify::{Locale, NOTIFICATION_LOCALE};
    use axum::{Json, body::Body, http::header, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn notification_locale_prefers_headers_for_json_and_cookie_for_navigation() {
        let app = Router::new()
            .route(
                "/",
                get(|| async { Json(NOTIFICATION_LOCALE.with(|locale| *locale)) }),
            )
            .layer(middleware::from_fn(notification_language));

        for (accept, expected) in [
            ("application/json", Locale::English),
            ("text/html", Locale::Chinese),
        ] {
            let request = Request::builder()
                .header(header::ACCEPT, accept)
                .header(header::ACCEPT_LANGUAGE, "en")
                .header(header::COOKIE, "pero_lang=zh-CN")
                .body(Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), 64)
                .await
                .unwrap();
            assert_eq!(serde_json::from_slice::<Locale>(&body).unwrap(), expected);
        }
    }
}
