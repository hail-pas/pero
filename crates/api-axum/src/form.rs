use askama::Template;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::csrf::{CsrfConfig, ensure_csrf};

pub fn render_askama_with_csrf<T, F>(jar: CookieJar, csrf: &CsrfConfig<'_>, build: F) -> Response
where
    T: Template,
    F: FnOnce(String) -> T,
{
    let (jar, csrf_token) = ensure_csrf(jar, csrf);
    match build(csrf_token).render() {
        Ok(html) => (jar, axum::response::Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
