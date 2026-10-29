//! A guided client setup and an opt-in diagnostic authorization flow.
use super::{
    dto::{AppSummary, ClientSummary, DashboardLayout},
    guard::{AdminContext, AdminPage},
};
use crate::service::integration::{self, callback_uri};
use crate::{
    db::{entity::apps, enums::CommonStatus},
    service::ManagementError,
    state::app::AppState,
    web::util,
};
use axum::{
    Form,
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Default, Deserialize)]
pub struct ListQuery {
    client: Option<Uuid>,
    test: Option<String>,
    #[serde(default)]
    test_error: String,
}
#[derive(Serialize)]
struct Check {
    code: &'static str,
    passed: bool,
}
#[derive(Serialize)]
struct IntegrationView {
    layout: DashboardLayout,
    csrf_token: String,
    app: AppSummary,
    clients: Vec<ClientSummary>,
    selected_client: Option<Uuid>,
    issuer: String,
    callback_uri: String,
    checks: Vec<Check>,
    test: String,
    test_ready: bool,
    test_success: bool,
    error: String,
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Response {
    match page(&state, jar, admin, id, query, false).await {
        Ok(response) => response,
        Err(e) => util::management_response(Err(e)),
    }
}
async fn page(
    state: &AppState,
    jar: CookieJar,
    admin: AdminContext,
    id: Uuid,
    query: ListQuery,
    success: bool,
) -> Result<Response, ManagementError> {
    let app = apps::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    let clients = crate::db::helper::admin::list_clients_by_app(&state.db, id).await?;
    let selected = match query.client {
        Some(id) => Some(
            clients
                .iter()
                .find(|c| c.id == id)
                .ok_or(ManagementError::Invalid("not_found"))?,
        ),
        None => clients.first(),
    };
    let mut checks = vec![
        Check {
            code: "app_active",
            passed: app.status == CommonStatus::Active,
        },
        Check {
            code: "signing_key",
            passed: crate::db::helper::signing_key::find_active_signing_key(&state.db)
                .await?
                .is_some_and(|key| {
                    key.private_key_pem.as_deref().is_some_and(|private| {
                        pero_utils::oauth::jwk::validate_signing_key(
                            &key.key.public_key_pem,
                            Some(private),
                        )
                        .is_ok()
                    })
                }),
        },
    ];
    let callback_uri = callback_uri(state);
    if let Some(c) = selected {
        checks.extend([
            Check {
                code: "client_active",
                passed: c.status == CommonStatus::Active,
            },
            Check {
                code: "openid",
                passed: c.scopes.iter().any(|s| s == "openid"),
            },
            Check {
                code: "code_grant",
                passed: c.grant_types.iter().any(|s| s == "authorization_code"),
            },
            Check {
                code: "pkce",
                passed: c.require_pkce,
            },
            Check {
                code: "redirects",
                passed: !c.redirect_uris.is_empty()
                    && pero_utils::redirect::validate_oauth_redirect_uris(&c.redirect_uris).is_ok(),
            },
            Check {
                code: "membership",
                passed: crate::service::access::active_app_access(&state.db, admin.user.id, id)
                    .await?
                    .is_some(),
            },
            Check {
                code: "test_callback",
                passed: c.redirect_uris.contains(&callback_uri),
            },
        ]);
    }
    let selected_client = selected.map(|c| c.id);
    let mut test = query.test.unwrap_or_default();
    let mut expired = query.test_error == "expired";
    let test_ready = if test.is_empty() {
        false
    } else {
        match integration::flow(state, &test, &admin.session, id).await {
            Ok(value) if Some(value.client_id) == selected_client => value.code.is_some(),
            Ok(_) | Err(ManagementError::Invalid("integration_test_expired")) => {
                test.clear();
                expired = true;
                false
            }
            Err(e) => return Err(e),
        }
    };
    let AdminPage {
        layout,
        csrf_token,
        jar,
    } = AdminPage::new(state, jar, admin);
    Ok(util::view_response(
        "IntegrationView",
        IntegrationView {
            layout,
            csrf_token,
            app: app.into(),
            clients: clients.into_iter().map(Into::into).collect(),
            selected_client,
            issuer: state.config.oidc.issuer.clone(),
            callback_uri,
            checks,
            test,
            test_ready,
            test_success: success,
            error: if expired {
                "integration_test_expired".into()
            } else if query.test_error == "access_denied" {
                "integration_access_denied".into()
            } else if !query.test_error.is_empty() {
                "integration_authorization_failed".into()
            } else {
                String::new()
            },
        },
        jar,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    csrf_token: String,
    action: String,
    client_id: Uuid,
    #[serde(default)]
    test: String,
    client_secret: Option<String>,
}
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    source: pero_api_axum::extractor::ClientIp,
    Form(input): Form<Input>,
) -> Response {
    if let Some(r) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return r;
    }
    let result = match input.action.as_str() {
        "start" => integration::start(&state, &admin.session, id, input.client_id)
            .await
            .map(|url| axum::Json(serde_json::json!({"redirect":url})).into_response()),
        "finish" => match integration::finish(
            &state,
            &admin.session,
            id,
            input.client_id,
            &input.test,
            input.client_secret,
            &source.for_rate_limit(),
        )
        .await
        {
            Ok(()) => {
                page(
                    &state,
                    jar,
                    admin,
                    id,
                    ListQuery {
                        client: Some(input.client_id),
                        ..Default::default()
                    },
                    true,
                )
                .await
            }
            Err(ManagementError::Invalid("integration_test_expired")) => {
                page(
                    &state,
                    jar,
                    admin,
                    id,
                    ListQuery {
                        client: Some(input.client_id),
                        test_error: "expired".into(),
                        ..Default::default()
                    },
                    false,
                )
                .await
            }
            Err(e) => Err(e),
        },
        _ => Err(ManagementError::Invalid("invalid_request")),
    };
    match result {
        Ok(response) => response,
        Err(e) => util::management_response(Err(e)),
    }
}

#[derive(Deserialize)]
pub struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
/// A protocol callback, deliberately outside SPA page interception.
pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<Callback>,
) -> Response {
    let session = match crate::web::session::extract_session(&state, &jar).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return util::management_response(Err(ManagementError::Invalid("unauthorized")));
        }
        Err(status) => return status.into_response(),
    };
    match integration::complete_callback(&state, &session, &query.state, query.code, query.error)
        .await
    {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(ManagementError::Invalid("integration_test_expired")) => {
            Redirect::to("/dashboard/apps").into_response()
        }
        Err(e) => util::management_response(Err(e)),
    }
}

#[derive(Deserialize)]
pub struct DiagnosticQuery {
    request: Uuid,
}

/// Execute the normal authorization decision for a server-created diagnostic request.
pub async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<DiagnosticQuery>,
) -> Response {
    let session = match crate::web::session::extract_session(&state, &jar).await {
        Ok(Some(session)) => session,
        Ok(None) => return Redirect::to("/dashboard/apps").into_response(),
        Err(status) => return status.into_response(),
    };
    let request = match integration::authorization_request(&state, &session, query.request).await {
        Ok(request) => request,
        Err(ManagementError::Invalid("integration_test_expired")) => {
            return Redirect::to("/dashboard/apps").into_response();
        }
        Err(error) => return util::management_response(Err(error)),
    };
    match crate::web::oauth2::authorize::resolve_authorization(&state, &jar, &request).await {
        Ok(response) => response.into_response(),
        Err(error) => error.into_response(),
    }
}
