use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::db::enums::IdentityProviderKind;
use crate::state::app::AppState;
use crate::web::dashboard::dto::{
    ProviderDetailView, ProviderFormData, ProviderFormView, ProviderListView,
};
use crate::web::dashboard::guard::{AdminContext, AdminPage};
use crate::web::util::{self, CsrfOnly, view_response};
use pero_api_axum::{json_error, json_ok};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ListQuery>,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);

    let page = query.page.unwrap_or(1).max(1);

    let (providers_list, total_pages) =
        match crate::db::helper::admin::list_providers(&state.db, page).await {
            Ok(data) => data,
            Err(error) => return util::dependency_error(error),
        };

    let tpl = ProviderListView {
        layout,
        csrf_token,
        providers: providers_list.into_iter().map(Into::into).collect(),
        page,
        total_pages,
    };
    view_response("ProviderListView", tpl, jar)
}

pub async fn new_form(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);

    let tpl = ProviderFormView {
        layout,
        csrf_token,
        mode: "create".to_owned(),
        provider_id: String::new(),
        form: ProviderFormData {
            kind: "oidc".to_owned(),
            scopes: "openid,profile,email".to_owned(),
            ..Default::default()
        },
        error: String::new(),
    };
    view_response("ProviderFormView", tpl, jar)
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ProviderFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    let kind = match IdentityProviderKind::try_from_str(&form.kind) {
        Ok(kind) => kind,
        Err(_) => return json_error("invalid_provider_kind"),
    };
    let input = match provider_input(&form) {
        Ok(input) => input,
        Err(error) => return json_error(&error),
    };
    match crate::service::provider::create(&state.db, form.code.trim(), kind, input).await {
        Ok(_) => json_ok(),
        Err(error) => provider_error(error),
    }
}

pub async fn detail(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);
    let provider = match crate::db::helper::admin::find_provider_by_id(&state.db, id).await {
        Ok(Some(p)) => p,
        Err(error) => return util::dependency_error(error),
        _ => return Redirect::to("/dashboard/providers").into_response(),
    };

    let keys = match crate::db::helper::admin::list_keys_by_provider(&state.db, provider.id).await {
        Ok(data) => data,
        Err(error) => return util::dependency_error(error),
    };

    let tpl = ProviderDetailView {
        layout,
        csrf_token,
        provider: provider.into(),
        keys: keys.into_iter().map(Into::into).collect(),
        error: String::new(),
    };
    view_response("ProviderDetailView", tpl, jar)
}

pub async fn edit_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);
    let provider = match crate::db::helper::admin::find_provider_by_id(&state.db, id).await {
        Ok(Some(p)) => p,
        Err(error) => return util::dependency_error(error),
        _ => return Redirect::to("/dashboard/providers").into_response(),
    };
    if provider.kind == IdentityProviderKind::Local {
        return Redirect::to(&format!("/dashboard/providers/{}", provider.id)).into_response();
    }

    let tpl = ProviderFormView {
        layout,
        csrf_token,
        mode: "edit".to_owned(),
        provider_id: provider.id.to_string(),
        form: ProviderFormData {
            csrf_token: String::new(),
            code: provider.code.clone(),
            name: provider.name.clone(),
            kind: provider.kind.to_string(),
            icon: provider
                .settings
                .get("icon")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            issuer: provider.issuer.unwrap_or_default(),
            authorization_endpoint: provider.authorization_endpoint.unwrap_or_default(),
            token_endpoint: provider.token_endpoint.unwrap_or_default(),
            userinfo_endpoint: provider.userinfo_endpoint.unwrap_or_default(),
            jwks_uri: provider.jwks_uri.unwrap_or_default(),
            end_session_endpoint: provider.end_session_endpoint.unwrap_or_default(),
            client_id: provider.client_id.unwrap_or_default(),
            client_secret: String::new(),
            scopes: provider.scopes.join(","),
            settings: {
                let mut s = provider.settings.clone();
                if let Some(obj) = s.as_object_mut() {
                    obj.remove("icon");
                }
                serde_json::to_string_pretty(&s).unwrap_or_default()
            },
            allow_registration: provider
                .settings
                .get("allow_registration")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            enabled: provider.enabled,
        },
        error: String::new(),
    };
    view_response("ProviderFormView", tpl, jar)
}

pub async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<ProviderFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let input = match provider_input(&form) {
        Ok(input) => input,
        Err(error) => return json_error(&error),
    };
    match crate::service::provider::update(&state.db, id, input).await {
        Ok(_) => json_ok(),
        Err(error) => provider_error(error),
    }
}

pub async fn toggle_enabled(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    match crate::service::provider::toggle_enabled(&state.db, id).await {
        Ok(()) => json_ok(),
        Err(error) => provider_error(error),
    }
}

fn provider_error(error: crate::service::provider::ProviderError) -> Response {
    match error {
        crate::service::provider::ProviderError::Invalid(code) => json_error(code),
        crate::service::provider::ProviderError::Database(error) => util::dependency_error(error),
    }
}

fn provider_input(
    form: &ProviderFormData,
) -> Result<crate::service::provider::ProviderInput, String> {
    Ok(crate::service::provider::ProviderInput {
        name: form.name.trim().to_owned(),
        issuer: util::empty_or_opt(&form.issuer),
        authorization_endpoint: util::empty_or_opt(&form.authorization_endpoint),
        token_endpoint: util::empty_or_opt(&form.token_endpoint),
        userinfo_endpoint: util::empty_or_opt(&form.userinfo_endpoint),
        jwks_uri: util::empty_or_opt(&form.jwks_uri),
        end_session_endpoint: util::empty_or_opt(&form.end_session_endpoint),
        client_id: util::empty_or_opt(&form.client_id),
        client_secret: form.client_secret.trim().to_owned(),
        scopes: util::parse_comma_list(&form.scopes),
        settings: {
            let mut settings =
                merge_icon_into_settings(parse_settings_json(&form.settings)?, &form.icon);
            settings["allow_registration"] = form.allow_registration.into();
            settings
        },
        enabled: form.enabled,
    })
}

fn parse_settings_json(s: &str) -> Result<serde_json::Value, String> {
    if s.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let settings: serde_json::Value =
        serde_json::from_str(s).map_err(|_| "invalid_settings_json".to_owned())?;
    if !settings.is_object() {
        return Err("invalid_settings_json".to_owned());
    }
    Ok(settings)
}

fn merge_icon_into_settings(mut settings: serde_json::Value, icon: &str) -> serde_json::Value {
    let normalized = crate::service::provider::normalize_icon(icon);
    if let Some(obj) = settings.as_object_mut() {
        if normalized.is_empty() {
            obj.remove("icon");
        } else {
            obj.insert(
                "icon".to_owned(),
                serde_json::Value::String(normalized.to_owned()),
            );
        }
    }
    settings
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_settings_require_a_json_object() {
        assert!(super::parse_settings_json("[]").is_err());
        assert!(super::parse_settings_json("null").is_err());
        assert!(super::parse_settings_json("{}").is_ok());
    }
}
