use super::permissions::{self, Actor};
// Provider configuration invariants shared by creation, edits and activation.
use crate::db::{entity::identity_providers as ip, enums::IdentityProviderKind};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait,
};

pub async fn enabled_social(db: &DatabaseConnection) -> Result<Vec<ip::Model>, sea_orm::DbErr> {
    ip::Entity::find()
        .filter(ip::Column::Kind.ne(IdentityProviderKind::Local))
        .filter(ip::Column::Enabled.eq(true))
        .all(db)
        .await
}

pub fn normalize_icon(raw: &str) -> &'static str {
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

/// Hold the provider policy through linking/session creation so disablement
/// cannot be bypassed by a previously validated callback or cached link.
pub(crate) async fn require_enabled_social<C: ConnectionTrait>(
    db: &C,
    id: uuid::Uuid,
) -> Result<(), pero_error::AppError> {
    let provider = ip::Entity::find_by_id(id)
        .lock_shared()
        .one(db)
        .await
        .map_err(|error| {
            pero_error::AppError::dependency_failure(
                "provider_query_failed",
                "Identity provider unavailable",
            )
            .with_source(error)
        })?;
    if !provider.is_some_and(|provider| provider.enabled && provider.kind.is_social()) {
        return Err(pero_error::AppError::unauthorized(
            "provider_unavailable",
            "Identity provider is disabled or unavailable",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum ProviderError {
    Invalid(&'static str),
    Database(sea_orm::DbErr),
    Management(super::ManagementError),
}
impl From<sea_orm::DbErr> for ProviderError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Database(error)
    }
}

pub struct ProviderInput {
    pub name: String,
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub client_id: Option<String>,
    /// An empty value preserves the existing secret on edit.
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub settings: serde_json::Value,
    pub enabled: bool,
}

impl ProviderInput {
    fn validate_identity_namespace(&self, current: &ip::Model) -> Result<(), ProviderError> {
        // A configured namespace is permanent, including while login callbacks are in flight.
        // New identity sources must get a new provider ID instead of inheriting old subjects.
        for (old, new) in [
            (&current.issuer, &self.issuer),
            (&current.client_id, &self.client_id),
        ] {
            if old.is_some() && old != new {
                return Err(ProviderError::Invalid(
                    "provider_identity_namespace_immutable",
                ));
            }
        }
        if current.kind != IdentityProviderKind::Oidc
            && current.userinfo_endpoint.is_some()
            && current.userinfo_endpoint != self.userinfo_endpoint
        {
            return Err(ProviderError::Invalid(
                "provider_identity_namespace_immutable",
            ));
        }
        Ok(())
    }

    fn apply(self, active: &mut ip::ActiveModel) -> String {
        active.name = Set(self.name);
        active.issuer = Set(self.issuer);
        active.authorization_endpoint = Set(self.authorization_endpoint);
        active.token_endpoint = Set(self.token_endpoint);
        active.userinfo_endpoint = Set(self.userinfo_endpoint);
        active.jwks_uri = Set(self.jwks_uri);
        active.end_session_endpoint = Set(self.end_session_endpoint);
        active.client_id = Set(self.client_id);
        active.scopes = Set(self.scopes);
        active.settings = Set(self.settings);
        active.enabled = Set(self.enabled);
        active.updated_at = Set(time::OffsetDateTime::now_utc());
        self.client_secret
    }
}

fn editable(kind: &IdentityProviderKind) -> Result<(), ProviderError> {
    if !kind.is_social() {
        return Err(ProviderError::Invalid("local_provider_protected"));
    }
    Ok(())
}

/// Disabled drafts may be incomplete, but any supplied endpoints must remain safe.
pub fn validate_configuration(provider: &ip::Model, has_secret: bool) -> Result<(), ProviderError> {
    editable(&provider.kind)?;
    if provider.name.trim().is_empty() {
        return Err(ProviderError::Invalid("name_required"));
    }
    for endpoint in [
        &provider.authorization_endpoint,
        &provider.token_endpoint,
        &provider.userinfo_endpoint,
        &provider.jwks_uri,
        &provider.end_session_endpoint,
    ] {
        pero_utils::redirect::validate_optional_provider_endpoint_uri(endpoint.as_deref())
            .map_err(|_| ProviderError::Invalid("invalid_provider_endpoint"))?;
    }
    if let Some(endpoint) = provider.settings.get("emails_endpoint") {
        let endpoint = endpoint
            .as_str()
            .ok_or(ProviderError::Invalid("invalid_provider_endpoint"))?;
        pero_utils::redirect::validate_optional_provider_endpoint_uri(Some(endpoint))
            .map_err(|_| ProviderError::Invalid("invalid_provider_endpoint"))?;
    }
    if provider.enabled {
        for required in [
            &provider.authorization_endpoint,
            &provider.token_endpoint,
            &provider.userinfo_endpoint,
            &provider.client_id,
        ] {
            if required.as_deref().is_none_or(|v| v.trim().is_empty()) {
                return Err(ProviderError::Invalid("provider_misconfigured"));
            }
        }
        if provider.kind == IdentityProviderKind::Wechat && !has_secret {
            return Err(ProviderError::Invalid("secret_required"));
        }
        if provider.kind == IdentityProviderKind::Oidc
            && (provider.issuer.as_deref().is_none_or(str::is_empty)
                || provider.jwks_uri.as_deref().is_none_or(str::is_empty)
                || !provider.scopes.iter().any(|scope| scope == "openid"))
        {
            return Err(ProviderError::Invalid("provider_misconfigured"));
        }
    }
    Ok(())
}

pub async fn create(
    db: &DatabaseConnection,
    actor: &Actor,
    code: &str,
    kind: IdentityProviderKind,
    input: ProviderInput,
) -> Result<ip::Model, ProviderError> {
    editable(&kind)?;
    if code.is_empty() || input.name.is_empty() {
        return Err(ProviderError::Invalid("code_and_name_required"));
    }
    if matches!(code, "." | "..") {
        return Err(ProviderError::Invalid("invalid_provider_code"));
    }
    if ip::Entity::find()
        .filter(ip::Column::Code.eq(code))
        .one(db)
        .await?
        .is_some()
    {
        return Err(ProviderError::Invalid("code_exists"));
    }
    let now = time::OffsetDateTime::now_utc();
    let mut active = ip::ActiveModel {
        id: Set(uuid::Uuid::now_v7()),
        code: Set(code.to_owned()),
        kind: Set(kind),
        client_secret_enc: Set(None),
        created_at: Set(now),
        ..Default::default()
    };
    let secret = input.apply(&mut active);
    save(db, actor, active, &secret, true).await
}

pub async fn update(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
    input: ProviderInput,
) -> Result<ip::Model, ProviderError> {
    let txn = db.begin().await?;
    permissions::require_super(&txn, actor)
        .await
        .map_err(ProviderError::Management)?;
    let current = ip::Entity::find_by_id(id)
        .lock_exclusive()
        .one(&txn)
        .await?
        .ok_or(ProviderError::Invalid("not_found"))?;
    editable(&current.kind)?;
    input.validate_identity_namespace(&current)?;
    let mut active = current.into();
    let secret = input.apply(&mut active);
    let result = save_on(&txn, active, &secret, false).await?;
    txn.commit().await?;
    Ok(result)
}

async fn save(
    db: &DatabaseConnection,
    actor: &Actor,
    active: ip::ActiveModel,
    secret: &str,
    insert: bool,
) -> Result<ip::Model, ProviderError> {
    let txn = db.begin().await?;
    permissions::require_super(&txn, actor)
        .await
        .map_err(ProviderError::Management)?;
    let result = save_on(&txn, active, secret, insert).await?;
    txn.commit().await?;
    Ok(result)
}

async fn save_on(
    db: &sea_orm::DatabaseTransaction,
    active: ip::ActiveModel,
    secret: &str,
    insert: bool,
) -> Result<ip::Model, ProviderError> {
    use sea_orm::TryIntoModel;
    let candidate = active.clone().try_into_model()?;
    validate_configuration(
        &candidate,
        !secret.is_empty() || candidate.client_secret_enc.is_some(),
    )?;
    let saved = if insert {
        active.insert(db).await?
    } else {
        active.update(db).await?
    };
    if !secret.is_empty() {
        crate::db::crypto_expr::update_provider_client_secret(db, secret, saved.id).await?;
    }
    Ok(saved)
}

pub async fn toggle_enabled(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
) -> Result<(), ProviderError> {
    let txn = db.begin().await?;
    permissions::require_super(&txn, actor)
        .await
        .map_err(ProviderError::Management)?;
    let mut current = ip::Entity::find_by_id(id)
        .lock_exclusive()
        .one(&txn)
        .await?
        .ok_or(ProviderError::Invalid("not_found"))?;
    current.enabled = !current.enabled;
    validate_configuration(&current, current.client_secret_enc.is_some())?;
    let mut active: ip::ActiveModel = current.clone().into();
    active.enabled = Set(current.enabled);
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    active.update(&txn).await?;
    txn.commit().await?;
    Ok(())
}
