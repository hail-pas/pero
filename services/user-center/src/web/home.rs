use askama::Template;
use axum::response::{Html, IntoResponse, Response};

#[derive(Debug, Template)]
#[template(path = "home.html")]
pub struct HomeTemplate;

pub async fn home() -> Response {
    let tpl = HomeTemplate;
    match tpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Home template render error: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
