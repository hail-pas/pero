use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

use crate::csrf::{CsrfConfig, ensure_csrf};

#[derive(Serialize)]
struct ViewEnvelope<T> {
    view: &'static str,
    data: T,
}

/// Render UI data with an explicit wire name independent of Rust type names.
pub fn view<T: Serialize>(view: &'static str, data: T) -> Response {
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::Json(ViewEnvelope { view, data }),
    )
        .into_response()
}

pub fn view_with_csrf<T: Serialize, F: FnOnce(String) -> T>(
    jar: CookieJar,
    csrf: &CsrfConfig<'_>,
    name: &'static str,
    build: F,
) -> Response {
    let (jar, token) = ensure_csrf(jar, csrf);
    (jar, view(name, build(token))).into_response()
}
