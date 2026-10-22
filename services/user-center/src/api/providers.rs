use axum::extract::State;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;

use crate::db::entity::identity_providers as ip;
use crate::db::enums::IdentityProviderKind;
use crate::state::app::AppState;
use pero_api_axum::ApiResponse;

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
pub async fn providers(State(state): State<AppState>) -> ApiResponse<ProvidersResponse> {
    let rows = ip::Entity::find()
        .filter(ip::Column::Kind.ne(IdentityProviderKind::Local))
        .filter(ip::Column::Enabled.eq(true))
        .all(&state.db)
        .await
        .unwrap_or_default();

    let providers = rows
        .into_iter()
        .map(|p| {
            let icon = crate::web::sso::utility::normalize_provider_icon(
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

    ApiResponse::success(ProvidersResponse { providers })
}
