use axum::extract::State;
use serde::Serialize;

use crate::service::provider;
use crate::state::app::AppState;
use pero_api_axum::{ApiResponse, AppErrorResponder};

#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub code: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub icon: String,
}

#[derive(Debug, Serialize)]
pub struct ProvidersResponse {
    pub providers: Vec<ProviderInfo>,
}

/// GET /api/providers
///
/// 返回已启用的 social providers 列表，供 OAuth2 客户端（如 admin panel）使用
pub async fn providers(
    State(state): State<AppState>,
) -> Result<ApiResponse<ProvidersResponse>, AppErrorResponder> {
    let rows = provider::enabled_social(&state.db).await.map_err(|error| {
        AppErrorResponder(
            pero_error::AppError::new(
                pero_error::ErrorKind::ServiceUnavailable,
                "service_unavailable",
                "Identity providers unavailable",
            )
            .with_source(error),
        )
    })?;

    let providers = rows
        .into_iter()
        .map(|p| {
            let icon = provider::normalize_icon(
                p.settings
                    .get("icon")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
            .to_owned();
            ProviderInfo {
                code: p.code,
                name: p.name,
                icon,
            }
        })
        .collect();

    Ok(ApiResponse::success(ProvidersResponse { providers }))
}
