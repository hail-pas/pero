use pero_api_axum::ApiResponse;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
}

pub async fn health() -> ApiResponse<HealthStatus> {
    ApiResponse::success(HealthStatus {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}
