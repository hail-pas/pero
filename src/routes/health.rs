use crate::shared::response::ApiResponse;
use axum::Json;
use serde::Serialize;
use utoipa;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Health status", body = ApiResponse<HealthStatus>)
    )
)]
pub async fn health() -> Json<ApiResponse<HealthStatus>> {
    Json(ApiResponse::success(HealthStatus {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }))
}
