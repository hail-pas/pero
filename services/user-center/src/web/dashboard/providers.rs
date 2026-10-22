use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use serde::Deserialize;

use crate::db::entity::{identity_provider_keys, identity_providers};
use crate::db::enums::{IdentityProviderKind, KeyAlgorithm, KeyUse};
use crate::state::app::AppState;
use crate::web::dashboard::guard::{AdminContext, AdminPage};
use crate::web::dashboard::template::{
    KeyForm, ProviderDetailTemplate, ProviderFormData, ProviderFormTemplate, ProviderListTemplate,
};
use crate::web::util::{self, CsrfOnly, render_template};
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
    } = AdminPage::new(&state, jar, admin, "providers");

    let page = query.page.unwrap_or(1).max(1);

    let (providers_list, total_pages) = crate::db::helper::admin::list_providers(&state.db, page)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("List providers: {e}");
            (vec![], 0)
        });

    let tpl = ProviderListTemplate {
        layout,
        csrf_token,
        providers: providers_list,
        page,
        total_pages,
    };
    render_template(tpl, jar)
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
    } = AdminPage::new(&state, jar, admin, "providers");

    let tpl = ProviderFormTemplate {
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
    render_template(tpl, jar)
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
        Err(error) => provider_error(error, "create_failed"),
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
    } = AdminPage::new(&state, jar, admin, "providers");
    let provider = match crate::db::helper::admin::find_provider_by_id(&state.db, id).await {
        Ok(Some(p)) => p,
        _ => return Redirect::to("/dashboard/providers").into_response(),
    };

    let keys = crate::db::helper::admin::list_keys_by_provider(&state.db, provider.id)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("List keys: {e}");
            vec![]
        });

    let tpl = ProviderDetailTemplate {
        layout,
        csrf_token,
        provider,
        keys,
        error: String::new(),
    };
    render_template(tpl, jar)
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
    } = AdminPage::new(&state, jar, admin, "providers");
    let provider = match crate::db::helper::admin::find_provider_by_id(&state.db, id).await {
        Ok(Some(p)) => p,
        _ => return Redirect::to("/dashboard/providers").into_response(),
    };
    if provider.kind == IdentityProviderKind::Local {
        return Redirect::to(&format!("/dashboard/providers/{}", provider.id)).into_response();
    }

    let tpl = ProviderFormTemplate {
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
            enabled: if provider.enabled {
                Some("on".to_owned())
            } else {
                None
            },
        },
        error: String::new(),
    };
    render_template(tpl, jar)
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
        Err(error) => provider_error(error, "update_failed"),
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
        Err(error) => provider_error(error, "update_failed"),
    }
}

fn provider_error(error: crate::service::provider::ProviderError, fallback: &str) -> Response {
    match error {
        crate::service::provider::ProviderError::Invalid(code) => json_error(code),
        crate::service::provider::ProviderError::Database(error) => {
            tracing::error!(%error, "Provider configuration failed");
            json_error(fallback)
        }
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
        settings: merge_icon_into_settings(parse_settings_json(&form.settings)?, &form.icon),
        enabled: form.enabled.is_some(),
    })
}

pub async fn create_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<KeyForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    if form.kid.trim().is_empty() || form.public_key_pem.trim().is_empty() {
        return json_error("kid_and_public_key_required");
    }

    let algorithm = match KeyAlgorithm::try_from_str(form.algorithm.as_str()) {
        Ok(value) => value,
        Err(_) => return json_error("invalid_algorithm"),
    };
    if algorithm != KeyAlgorithm::Rs256 {
        return json_error("unsupported_signing_algorithm");
    }
    let key_use = match KeyUse::try_from_str(form.key_use.as_str()) {
        Ok(value) => value,
        Err(_) => return json_error("invalid_key_use"),
    };
    let private_key_pem = form.private_key_pem.trim();
    if let Err(e) = validate_key_activation_shape(
        key_use.clone(),
        form.active.is_some(),
        !private_key_pem.is_empty(),
    ) {
        return json_error(e);
    }
    if let Err(error) = pero_utils::oauth::jwk::validate_signing_key(
        form.public_key_pem.trim(),
        (!private_key_pem.is_empty()).then_some(private_key_pem),
    ) {
        return json_error(&error);
    }
    let (not_before, expires_at) = match (
        parse_optional_datetime(&form.not_before),
        parse_optional_datetime(&form.expires_at),
    ) {
        (Ok(start), Ok(end)) if start.zip(end).is_none_or(|(start, end)| start < end) => {
            (start, end)
        }
        _ => return json_error("invalid_key_dates"),
    };
    if form.active.is_some()
        && (not_before.is_some_and(|at| at > time::OffsetDateTime::now_utc())
            || expires_at.is_some_and(|at| at <= time::OffsetDateTime::now_utc()))
    {
        return json_error("key_not_currently_valid");
    }
    let now = time::OffsetDateTime::now_utc();
    let key_id = uuid::Uuid::now_v7();

    let model = identity_provider_keys::ActiveModel {
        id: Set(key_id),
        provider_id: Set(id),
        kid: Set(form.kid.trim().to_owned()),
        r#use: Set(key_use),
        algorithm: Set(algorithm),
        public_key_pem: Set(form.public_key_pem.trim().to_owned()),
        private_key_pem_enc: Set(None),
        certificate_pem: Set(util::empty_or_opt(&form.certificate_pem)),
        active: Set(form.active.is_some()),
        not_before: Set(not_before),
        expires_at: Set(expires_at),
        revoked_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let txn = match state.db.begin().await {
        Ok(txn) => txn,
        Err(e) => {
            tracing::error!("Create key transaction begin: {e}");
            return json_error("create_failed");
        }
    };

    if lock_key_provider(&txn, id).await.is_err() {
        return json_error("create_failed");
    }
    if form.active.is_some() && deactivate_signing_keys(&txn, id).await.is_err() {
        return json_error("create_failed");
    }

    if let Err(e) = model.insert(&txn).await {
        tracing::error!("Create key: {e}");
        return json_error("create_failed");
    }

    if !private_key_pem.is_empty()
        && let Err(e) =
            crate::db::crypto_expr::update_signing_key_private_key(&txn, private_key_pem, key_id)
                .await
    {
        tracing::error!("Encrypt signing private key: {e}");
        return json_error("create_failed");
    }

    match txn.commit().await {
        Ok(_) => json_ok(),
        Err(e) => {
            tracing::error!("Create key transaction commit: {e}");
            json_error("create_failed")
        }
    }
}

pub async fn activate_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((provider_id, kid)): Path<(uuid::Uuid, String)>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    let txn = match state.db.begin().await {
        Ok(txn) => txn,
        Err(_) => return json_error("update_failed"),
    };
    if lock_key_provider(&txn, provider_id).await.is_err() {
        return json_error("update_failed");
    }
    let key = identity_provider_keys::Entity::find()
        .expr_as(
            crate::db::crypto_expr::pgp_decrypt_expr(sea_orm::sea_query::Expr::col(
                identity_provider_keys::Column::PrivateKeyPemEnc,
            )),
            "private_key_pem",
        )
        .filter(identity_provider_keys::Column::ProviderId.eq(provider_id))
        .filter(identity_provider_keys::Column::Kid.eq(&kid))
        .into_model::<crate::db::helper::signing_key::SigningKeyRow>()
        .one(&txn)
        .await;
    let key = match key {
        Ok(Some(key)) => key,
        Ok(None) => return json_error("not_found"),
        Err(_) => return json_error("update_failed"),
    };
    let now = time::OffsetDateTime::now_utc();
    if key.key.revoked_at.is_some()
        || key.key.not_before.is_some_and(|at| at > now)
        || key.key.expires_at.is_some_and(|at| at <= now)
    {
        return json_error("key_not_currently_valid");
    }
    if key.key.algorithm != KeyAlgorithm::Rs256
        || key.key.r#use != KeyUse::Sig
        || key.private_key_pem.is_none()
    {
        return json_error("invalid_signing_key");
    }
    if let Err(error) = pero_utils::oauth::jwk::validate_signing_key(
        &key.key.public_key_pem,
        key.private_key_pem.as_deref(),
    ) {
        return json_error(&error);
    }
    if deactivate_signing_keys(&txn, provider_id).await.is_err() {
        return json_error("update_failed");
    }
    let mut active: identity_provider_keys::ActiveModel = key.key.into();
    active.active = Set(true);
    active.updated_at = Set(now);
    if active.update(&txn).await.is_err() || txn.commit().await.is_err() {
        return json_error("update_failed");
    }
    json_ok()
}

async fn lock_key_provider<C: ConnectionTrait>(
    db: &C,
    id: uuid::Uuid,
) -> Result<(), sea_orm::DbErr> {
    identity_providers::Entity::find_by_id(id)
        .lock_exclusive()
        .one(db)
        .await?
        .ok_or_else(|| sea_orm::DbErr::RecordNotFound("provider not found".into()))?;
    Ok(())
}

async fn deactivate_signing_keys<C: ConnectionTrait>(
    db: &C,
    id: uuid::Uuid,
) -> Result<(), sea_orm::DbErr> {
    // Retain previous public keys in JWKS for verification of unexpired tokens.
    identity_provider_keys::Entity::update_many()
        .col_expr(
            identity_provider_keys::Column::Active,
            sea_orm::sea_query::Expr::value(false),
        )
        .col_expr(
            identity_provider_keys::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(time::OffsetDateTime::now_utc()),
        )
        .filter(identity_provider_keys::Column::ProviderId.eq(id))
        .filter(identity_provider_keys::Column::Use.eq(KeyUse::Sig))
        .filter(identity_provider_keys::Column::Active.eq(true))
        .exec(db)
        .await?;
    Ok(())
}

pub async fn revoke_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((provider_id, kid)): Path<(uuid::Uuid, String)>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    let key = match identity_provider_keys::Entity::find()
        .filter(identity_provider_keys::Column::ProviderId.eq(provider_id))
        .filter(identity_provider_keys::Column::Kid.eq(&kid))
        .one(&state.db)
        .await
    {
        Ok(value) => value,
        Err(_) => return json_error("internal_error"),
    };

    match key {
        Some(k) => {
            let mut active: identity_provider_keys::ActiveModel = k.into();
            active.active = Set(false);
            active.revoked_at = Set(Some(time::OffsetDateTime::now_utc()));
            active.updated_at = Set(time::OffsetDateTime::now_utc());
            match active.update(&state.db).await {
                Ok(_) => json_ok(),
                Err(e) => {
                    tracing::error!("Revoke key: {e}");
                    json_error("update_failed")
                }
            }
        }
        None => json_error("not_found"),
    }
}

fn parse_optional_datetime(s: &str) -> Result<Option<time::OffsetDateTime>, ()> {
    if s.trim().is_empty() {
        return Ok(None);
    }
    time::OffsetDateTime::parse(s.trim(), &time::format_description::well_known::Rfc3339)
        .map(Some)
        .map_err(|_| ())
}

fn parse_settings_json(s: &str) -> Result<serde_json::Value, String> {
    if s.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(s).map_err(|_| "invalid_settings_json".to_owned())
}

fn validate_key_activation_shape(
    key_use: KeyUse,
    active: bool,
    has_private_key: bool,
) -> Result<(), &'static str> {
    if active && key_use == KeyUse::Sig && !has_private_key {
        return Err("private_key_required_for_active_signing_key");
    }
    Ok(())
}

fn merge_icon_into_settings(mut settings: serde_json::Value, icon: &str) -> serde_json::Value {
    let normalized = crate::web::sso::utility::normalize_provider_icon(icon);
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
