use axum::extract::State;
use axum::response::Response;

use crate::service::provider;
use crate::state::app::AppState;
use crate::web::sso::dto::{ErrorView, SocialProvider};

/// EP-26: GET /sso/error?code=xxx — 渲染错误页面
pub async fn error_page(
    State(_state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let code = params.get("code").cloned().unwrap_or_default();
    let tpl = ErrorView { code };
    pero_api_axum::form::view("ErrorView", tpl)
}

pub(crate) async fn find_enabled_social_providers(
    state: &AppState,
) -> Result<Vec<SocialProvider>, sea_orm::DbErr> {
    Ok(provider::enabled_social(&state.db)
        .await?
        .into_iter()
        .map(|provider| SocialProvider {
            icon: provider::normalize_icon(
                provider
                    .settings
                    .get("icon")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            )
            .to_owned(),
            key: provider.code,
            name: provider.name,
        })
        .collect())
}
