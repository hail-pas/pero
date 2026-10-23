use axum::extract::State;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde::de::Deserializer;

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

pub(crate) async fn find_enabled_social_providers(
    state: &AppState,
) -> Result<Vec<SocialProvider>, Response> {
    Ok(provider::enabled_social(&state.db)
        .await
        .map_err(crate::web::util::dependency_error)?
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

pub(crate) fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(pero_utils::string::normalize_optional_string(opt))
}
