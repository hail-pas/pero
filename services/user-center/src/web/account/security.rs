use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QueryTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::dto::AccountLayout;
use crate::{
    db::{
        entity::{
            apps, identities, identity_providers, login_events, oauth_clients, sso_sessions,
            user_consents, users,
        },
        enums::IdentityKind,
    },
    state::{app::AppState, session::SsoSession},
    web::{
        dashboard::guard::AdminContext,
        session::extract_session,
        util::{self, CsrfOnly},
    },
};

pub struct AccountContext {
    pub session: SsoSession,
    pub user: users::Model,
}

impl FromRequestParts<AppState> for AccountContext {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let jar = CookieJar::from_headers(&parts.headers);
        let session = extract_session(state, &jar)
            .await
            .map_err(IntoResponse::into_response)?
            .ok_or_else(|| {
                let mut url = "/account/login".to_owned();
                // A mutation endpoint cannot be resumed by browser navigation after login.
                let target = if parts.method == axum::http::Method::POST {
                    format!(
                        "/account/{}",
                        parts.uri.path().split('/').nth(2).unwrap_or("profile")
                    )
                } else {
                    parts.uri.to_string()
                };
                pero_utils::encode::append_query_param(&mut url, "redirect", &target);
                Redirect::to(&url).into_response()
            })?;
        let user = users::Entity::find_by_id(session.user_id)
            .one(&state.db)
            .await
            .map_err(util::dependency_error)?
            .ok_or_else(|| Redirect::to("/account/login").into_response())?;
        Ok(Self { session, user })
    }
}

#[derive(Default, Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
    #[serde(default)]
    pub event_type: String,
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub q: String,
    pub ip: Option<ipnetwork::IpNetwork>,
    pub provider_id: Option<Uuid>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<time::OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<time::OffsetDateTime>,
}

#[derive(Serialize)]
pub struct AccountListView<T: Serialize> {
    pub layout: AccountLayout,
    pub csrf_token: String,
    pub rows: Vec<T>,
    pub page: u64,
    pub total_pages: u64,
}

async fn render<T: Serialize>(
    state: &AppState,
    jar: CookieJar,
    user: &users::Model,
    view: &'static str,
    rows: Vec<T>,
    pagination: (u64, u64),
) -> Response {
    let (page, total_pages) = pagination;
    let layout = match AccountLayout::from_user(&state.db, user).await {
        Ok(layout) => layout,
        Err(error) => return crate::web::util::dependency_error(error),
    };
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        view,
        AccountListView {
            layout,
            csrf_token,
            rows,
            page,
            total_pages,
        },
        jar,
    )
}

#[derive(Serialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub current: bool,
    pub authentication_pending: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

impl SessionRow {
    pub fn new(s: sso_sessions::Model, current: Uuid) -> Self {
        Self {
            id: s.id,
            ip: s.ip.map(|ip| ip.to_string()),
            user_agent: s.user_agent,
            current: s.id == current,
            authentication_pending: s.recovery_pending
                || s.mfa_required && s.mfa_verified_at.is_none(),
            created_at: s.created_at,
            last_seen_at: s.last_seen_at,
            expires_at: s.expires_at,
        }
    }
}

pub async fn sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Query(query): Query<ListQuery>,
) -> Response {
    let page = query.page.unwrap_or(1).max(1);
    let paginator = crate::db::helper::session::valid_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
    )
    .filter(sso_sessions::Column::UserId.eq(account.user.id))
    .order_by_desc(sso_sessions::Column::CreatedAt)
    .order_by_desc(sso_sessions::Column::Id)
    .paginate(&state.db, crate::config::DASHBOARD_PAGE_SIZE);
    let result = async {
        Ok::<_, sea_orm::DbErr>((
            paginator.fetch_page(page - 1).await?,
            paginator.num_pages().await?,
        ))
    }
    .await;
    let (rows, total_pages) = match result {
        Ok(value) => value,
        Err(error) => return util::dependency_error(error),
    };
    let rows = rows
        .into_iter()
        .map(|s| SessionRow::new(s, account.session.id))
        .collect();
    render(
        &state,
        jar,
        &account.user,
        "SessionListView",
        rows,
        (page, total_pages),
    )
    .await
}

#[derive(Deserialize)]
pub struct RevokeSessionsForm {
    pub csrf_token: String,
    pub scope: String,
    pub session_id: Option<Uuid>,
}

pub async fn revoke_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    axum::Form(form): axum::Form<RevokeSessionsForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let (selection, logout) = match form.scope.as_str() {
        "one" => match form.session_id {
            Some(id) => (
                Condition::all().add(sso_sessions::Column::Id.eq(id)),
                id == account.session.id,
            ),
            None => return pero_api_axum::json_error("not_found"),
        },
        "others" => (
            Condition::all().add(sso_sessions::Column::Id.ne(account.session.id)),
            false,
        ),
        "all" => (Condition::all(), true),
        _ => return pero_api_axum::json_error("invalid_request"),
    };
    let result = crate::service::account_security::revoke_account_sessions(
        &state.db,
        &account.session,
        &state.config.sso,
        selection,
    )
    .await;
    match result {
        Err(error) => util::management_response(Err(error)),
        Ok(()) if logout => {
            let cookies = state.cookie_factory();
            (
                jar.add(cookies.clear_cookie(cookies.session_cookie_name())),
                Redirect::to("/account/login"),
            )
                .into_response()
        }
        Ok(()) => pero_api_axum::json_ok(),
    }
}

#[derive(Serialize)]
pub struct ActivityRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub username: String,
    pub provider_name: String,
    pub event_type: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

pub async fn activity(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Query(query): Query<ListQuery>,
) -> Response {
    activity_page(&state, jar, &account.user, Some(account.user.id), query).await
}
pub async fn admin_activity(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Query(query): Query<ListQuery>,
) -> Response {
    activity_page(&state, jar, &admin.user, query.user_id, query).await
}
async fn activity_page(
    state: &AppState,
    jar: CookieJar,
    viewer: &users::Model,
    user_id: Option<Uuid>,
    query: ListQuery,
) -> Response {
    let page = query.page.unwrap_or(1).max(1);
    if query.from.zip(query.to).is_some_and(|(from, to)| from > to) {
        return pero_api_axum::json_error("invalid_request");
    }
    let mut select = login_events::Entity::find();
    if let Some(ip) = query.ip {
        select = select.filter(login_events::Column::Ip.eq(ip));
    }
    if let Some(id) = query.provider_id {
        select = select.filter(login_events::Column::ProviderId.eq(id));
    }
    if let Some(from) = query.from {
        select = select.filter(login_events::Column::CreatedAt.gte(from));
    }
    if let Some(to) = query.to {
        select = select.filter(login_events::Column::CreatedAt.lte(to));
    }
    if !query.q.is_empty() {
        use sea_orm::QuerySelect;
        select = select.filter(
            login_events::Column::UserId.in_subquery(
                users::Entity::find()
                    .select_only()
                    .column(users::Column::Id)
                    .filter(users::Column::Username.contains(&query.q))
                    .into_query(),
            ),
        );
    }
    if let Some(id) = user_id {
        select = select.filter(login_events::Column::UserId.eq(id));
    }
    if !query.event_type.is_empty() {
        let event = match crate::db::enums::LoginEventType::try_from_str(&query.event_type) {
            Ok(event) => event,
            Err(_) => return pero_api_axum::json_error("invalid_request"),
        };
        select = select.filter(login_events::Column::EventType.eq(event));
    }
    let paginator = select
        .order_by_desc(login_events::Column::CreatedAt)
        .order_by_desc(login_events::Column::Id)
        .paginate(&state.db, crate::config::DASHBOARD_PAGE_SIZE);
    let result = async {
        let total_pages = paginator.num_pages().await?;
        let events = paginator.fetch_page(page - 1).await?;
        let user_ids: Vec<_> = events.iter().filter_map(|event| event.user_id).collect();
        let provider_ids: Vec<_> = events
            .iter()
            .filter_map(|event| event.provider_id)
            .collect();
        let users = users::Entity::find()
            .filter(users::Column::Id.is_in(user_ids))
            .all(&state.db)
            .await?;
        let providers = identity_providers::Entity::find()
            .filter(identity_providers::Column::Id.is_in(provider_ids))
            .all(&state.db)
            .await?;
        let rows = events
            .into_iter()
            .map(|event| ActivityRow {
                id: event.id,
                user_id: event.user_id,
                username: users
                    .iter()
                    .find(|user| Some(user.id) == event.user_id)
                    .map(|user| user.username.clone())
                    .unwrap_or_default(),
                provider_name: providers
                    .iter()
                    .find(|provider| Some(provider.id) == event.provider_id)
                    .map(|provider| provider.name.clone())
                    .unwrap_or_default(),
                event_type: event.event_type.to_string(),
                ip: event.ip.map(|ip| ip.to_string()),
                user_agent: event.user_agent,
                created_at: event.created_at,
            })
            .collect();
        Ok::<_, sea_orm::DbErr>((rows, total_pages))
    }
    .await;
    match result {
        Ok((rows, total)) => {
            render(state, jar, viewer, "ActivityListView", rows, (page, total)).await
        }
        Err(error) => util::dependency_error(error),
    }
}

#[derive(Serialize)]
pub struct AuthorizationRow {
    pub client_id: Uuid,
    pub client_name: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub granted_at: time::OffsetDateTime,
}
pub async fn authorizations(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Query(query): Query<ListQuery>,
) -> Response {
    let page = query.page.unwrap_or(1).max(1);
    let paginator = user_consents::Entity::find()
        .filter(user_consents::Column::UserId.eq(account.user.id))
        .order_by_desc(user_consents::Column::GrantedAt)
        .order_by_asc(user_consents::Column::ClientId)
        .paginate(&state.db, crate::config::DASHBOARD_PAGE_SIZE);
    let result = async {
        let total = paginator.num_pages().await?;
        let consents = paginator.fetch_page(page - 1).await?;
        let clients = oauth_clients::Entity::find()
            .filter(oauth_clients::Column::Id.is_in(consents.iter().map(|c| c.client_id)))
            .find_also_related(apps::Entity)
            .all(&state.db)
            .await?;
        let rows = consents
            .into_iter()
            .filter_map(|consent| {
                let (client, Some(app)) = clients
                    .iter()
                    .find(|(client, _)| client.id == consent.client_id)?
                else {
                    return None;
                };
                Some(AuthorizationRow {
                    client_id: client.id,
                    client_name: client
                        .name
                        .clone()
                        .unwrap_or_else(|| client.identifier.clone()),
                    app_id: app.id,
                    app_name: app.name.clone(),
                    scopes: consent.scopes,
                    granted_at: consent.granted_at,
                })
            })
            .collect();
        Ok::<_, sea_orm::DbErr>((rows, total))
    }
    .await;
    match result {
        Ok((rows, total)) => {
            render(
                &state,
                jar,
                &account.user,
                "AuthorizationListView",
                rows,
                (page, total),
            )
            .await
        }
        Err(error) => util::dependency_error(error),
    }
}
pub async fn revoke_authorization(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Path(id): Path<Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(
        crate::service::account_security::revoke_authorization(
            &state.db,
            &account.session,
            &state.config.sso,
            id,
        )
        .await,
    )
}

#[derive(Serialize)]
pub struct IdentityRow {
    pub id: Uuid,
    pub provider_name: String,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<time::OffsetDateTime>,
}
#[derive(Serialize)]
struct IdentityListView {
    layout: AccountLayout,
    csrf_token: String,
    rows: Vec<IdentityRow>,
    providers: Vec<super::super::sso::dto::SocialProvider>,
    has_password: bool,
    error: String,
}
pub async fn identities(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Query(query): Query<ListQuery>,
) -> Response {
    let identities = match identities::Entity::find()
        .filter(identities::Column::UserId.eq(account.user.id))
        .filter(identities::Column::UnboundAt.is_null())
        .order_by_asc(identities::Column::CreatedAt)
        .find_also_related(identity_providers::Entity)
        .all(&state.db)
        .await
    {
        Ok(rows) => rows,
        Err(error) => return util::dependency_error(error),
    };
    let has_password = identities
        .iter()
        .any(|(id, _)| id.kind == IdentityKind::Password && id.password_hash.is_some());
    let mut providers = match crate::web::sso::utility::find_enabled_social_providers(&state).await
    {
        Ok(providers) => providers,
        Err(response) => return response,
    };
    providers.retain(|provider| {
        !identities.iter().any(|(id, p)| {
            id.kind == IdentityKind::Oauth && p.as_ref().is_some_and(|p| p.code == provider.key)
        })
    });
    let rows = identities
        .into_iter()
        .filter_map(|(identity, provider)| {
            if identity.kind != IdentityKind::Oauth {
                return None;
            }
            let provider = provider?;
            Some(IdentityRow {
                id: identity.id,
                provider_name: provider.name,
                enabled: provider.enabled,
                last_login_at: identity.last_login_at,
            })
        })
        .collect();
    let layout = match AccountLayout::from_user(&state.db, &account.user).await {
        Ok(layout) => layout,
        Err(error) => return crate::web::util::dependency_error(error),
    };
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        "IdentityListView",
        IdentityListView {
            layout,
            csrf_token,
            rows,
            providers,
            has_password,
            error: query.error,
        },
        jar,
    )
}
pub async fn unlink(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Path(id): Path<Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    match crate::service::account_security::unlink_identity(
        &state.db,
        &account.session,
        &state.config.sso,
        id,
    )
    .await
    {
        Ok(()) if account.session.identity_id == Some(id) => {
            let cookies = state.cookie_factory();
            (
                jar.add(cookies.clear_cookie(cookies.session_cookie_name())),
                Redirect::to("/account/login"),
            )
                .into_response()
        }
        result => util::management_response(result),
    }
}
pub async fn link(
    State(state): State<AppState>,
    jar: CookieJar,
    account: AccountContext,
    Path(provider): Path<String>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let svc = state.social_service();
    let provider = match svc.find_provider_by_code(&provider).await {
        Ok(p) => p,
        Err(crate::service::social::SocialLoginError::ProviderNotFound) => {
            return pero_api_axum::json_error("unknown_provider");
        }
        Err(_) => return util::dependency_error("Identity provider lookup failed"),
    };
    let prepared = match svc
        .prepare_login_state(
            &provider,
            &provider.code,
            None,
            "/account/identities",
            Some((account.user.id, account.session.id)),
        )
        .await
    {
        Ok(p) => p,
        Err(crate::service::social::SocialLoginError::ProviderMisconfigured) => {
            return pero_api_axum::json_error("provider_misconfigured");
        }
        Err(_) => return util::dependency_error("Account linking state unavailable"),
    };
    let cookies = state.cookie_factory();
    let cookie = cookies.build_short_lived_cookie(
        &cookies.social_state_cookie_name(),
        &prepared.state_hash,
        state.config.oauth2.auth_code_ttl_seconds,
    );
    (jar.add(cookie), Redirect::to(&prepared.authorize_url)).into_response()
}
