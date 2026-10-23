use axum::response::Response;

#[derive(Debug, serde::Serialize)]
pub struct HomeView;

pub async fn home() -> Response {
    let tpl = HomeView;
    pero_api_axum::form::view("HomeView", tpl)
}
