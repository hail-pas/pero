use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use serde::de::Deserializer;

use crate::db::enums::IdentityProviderKind;
use crate::state::app::AppState;
use crate::web::sso::template::{ErrorTemplate, SocialProvider};

/// EP-26: GET /sso/error?code=xxx — 渲染错误页面
pub async fn error_page(
    State(_state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let code = params.get("code").cloned().unwrap_or_default();
    let tpl = ErrorTemplate { code };
    match tpl.render() {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn resolve_auth_request_id(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<uuid::Uuid>, pero_error::AppError> {
    let cookies = state.cookie_factory();
    let nonce_name = cookies.nonce_cookie_name();
    if let Some(c) = jar.get(&nonce_name) {
        let key_str = c.value();
        if let Ok(key) = crate::cache::key::pending_req.key(key_str)
            && let Some(val) = state
                .cache
                .get::<crate::cache::key::PendingReqValue>(key)
                .await?
            && let Ok(id) = uuid::Uuid::parse_str(&val.auth_request_id)
        {
            return Ok(Some(id));
        }
    }
    let req_name = cookies.auth_req_cookie_name();
    Ok(jar.get(&req_name).and_then(|c| {
        cookies
            .decode_auth_request(c.value())
            .ok()
            .map(|v| v.auth_request_id)
    }))
}

pub(crate) async fn find_enabled_social_providers(state: &AppState) -> Vec<SocialProvider> {
    use crate::db::entity::identity_providers as ip;

    ip::Entity::find()
        .filter(ip::Column::Kind.ne(IdentityProviderKind::Local))
        .filter(ip::Column::Enabled.eq(true))
        .all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|provider| SocialProvider {
            icon: normalize_provider_icon(
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
        .collect()
}

pub(crate) fn normalize_provider_icon(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "github" => "github",
        "gitlab" => "gitlab",
        "google" => "google",
        "microsoft" => "microsoft",
        "oauth2" => "oauth2",
        "oidc" => "oidc",
        "wechat" => "wechat",
        _ => "",
    }
}

pub(crate) fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(pero_utils::string::normalize_optional_string(opt))
}
