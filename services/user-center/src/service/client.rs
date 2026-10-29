use super::permissions::{self, Actor, Permission as P};
// Commit client policy changes and grant revocation as one operation.
use super::ManagementError;
use crate::db::{
    entity::{apps, oauth_clients},
    enums::{CommonStatus, OauthClientType},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};

pub(crate) async fn save_security_change(
    db: &DatabaseConnection,
    actor: &Actor,
    permission: P,
    expected: &oauth_clients::Model,
    mut active: oauth_clients::ActiveModel,
    revoke_reason: Option<&str>,
) -> Result<(), ManagementError> {
    if active.app_id.as_ref() != &expected.app_id {
        return Err(ManagementError::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, expected.app_id, permission).await?;
    // Provisioning exposes member profiles without individual consent. Only a super
    // administrator may enable/redirect it or change its field policy.
    if !access.super_admin
        && (active.account_sync_uri.as_ref() != &expected.account_sync_uri
            || expected.account_sync_uri.is_some() && active.scopes.as_ref() != &expected.scopes)
    {
        return Err(ManagementError::Invalid("forbidden"));
    }
    if permission == P::ClientsManage
        && (active.r#type.as_ref() != &expected.r#type
            || active.secret_hash.as_ref() != &expected.secret_hash)
    {
        access.require_app(expected.app_id, P::ClientsSecretRotate)?;
    }

    let current = oauth_clients::Entity::find_by_id(expected.id)
        .lock_exclusive()
        .one(&txn)
        .await?;
    // Hashing runs before this transaction; do not overwrite a concurrent policy edit.
    if current.as_ref() != Some(expected) {
        return Err(ManagementError::Invalid("policy_conflict"));
    }
    if revoke_reason.is_some() {
        active.token_version = Set(expected.token_version + 1);
    }
    let updated = active.update(&txn).await?;
    if let Some(reason) = revoke_reason {
        super::session::SessionService::revoke_client_grants(&txn, updated.id, reason).await?;
    }
    txn.commit().await?;
    Ok(())
}

pub struct ClientInput {
    pub client_type: OauthClientType,
    pub secret: String,
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub require_pkce: bool,
    pub access_token_ttl: i32,
    pub refresh_token_ttl: i32,
    pub id_token_ttl: i32,
}

impl ClientInput {
    fn validate(&self) -> Result<(), ManagementError> {
        if self.redirect_uris.is_empty() {
            return Err(ManagementError::Invalid("invalid_redirect_uri"));
        }
        for uris in [&self.redirect_uris, &self.post_logout_redirect_uris] {
            pero_utils::redirect::validate_oauth_redirect_uris(uris)
                .map_err(|_| ManagementError::Invalid("invalid_redirect_uri"))?;
        }
        Ok(())
    }

    fn apply(self, active: &mut oauth_clients::ActiveModel) {
        active.require_pkce = Set(self.require_pkce || self.client_type == OauthClientType::Public);
        if self.client_type == OauthClientType::Public {
            active.account_sync_uri = Set(None);
        }
        active.r#type = Set(self.client_type);
        active.name = Set(self.name);
        active.redirect_uris = Set(self.redirect_uris);
        active.post_logout_redirect_uris = Set(self.post_logout_redirect_uris);
        active.scopes = Set(self.scopes);
        active.grant_types = Set(self.grant_types);
        active.access_token_ttl_seconds = Set(self.access_token_ttl.max(60));
        active.refresh_token_ttl_seconds = Set(self.refresh_token_ttl.max(60));
        active.id_token_ttl_seconds = Set(self.id_token_ttl.max(60));
        active.updated_at = Set(time::OffsetDateTime::now_utc());
    }
}

async fn find(
    db: &DatabaseConnection,
    id: uuid::Uuid,
) -> Result<oauth_clients::Model, ManagementError> {
    oauth_clients::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))
}

pub async fn create(
    db: &DatabaseConnection,
    actor: &Actor,
    app_id: uuid::Uuid,
    identifier: &str,
    input: ClientInput,
) -> Result<Option<String>, ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, app_id, P::ClientsManage).await?;
    input.validate()?;
    if identifier.is_empty() {
        return Err(ManagementError::Invalid("identifier_required"));
    }
    if apps::Entity::find_by_id(app_id).one(&txn).await?.is_none() {
        return Err(ManagementError::Invalid("invalid_app"));
    }
    if oauth_clients::Entity::find()
        .filter(oauth_clients::Column::Identifier.eq(identifier))
        .one(&txn)
        .await?
        .is_some()
    {
        return Err(ManagementError::Invalid("identifier_exists"));
    }
    let secret = (input.client_type == OauthClientType::Confidential).then(|| {
        if input.secret.is_empty() {
            pero_utils::crypto::generate_token()
        } else {
            input.secret.clone()
        }
    });
    let hash = match &secret {
        Some(secret) => Some(pero_utils::crypto::hash_secret_async(secret).await?),
        None => None,
    };
    let mut active = oauth_clients::ActiveModel {
        id: Set(uuid::Uuid::now_v7()),
        app_id: Set(app_id),
        identifier: Set(identifier.to_owned()),
        secret_hash: Set(hash),
        status: Set(CommonStatus::Active),
        created_at: Set(time::OffsetDateTime::now_utc()),
        ..Default::default()
    };
    input.apply(&mut active);
    active.insert(&txn).await.map_err(|error| {
        if crate::db::error::is_unique_violation(&error) {
            ManagementError::Invalid("identifier_exists")
        } else {
            error.into()
        }
    })?;
    txn.commit().await?;
    Ok(secret)
}

pub async fn update(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
    input: ClientInput,
) -> Result<(), ManagementError> {
    input.validate()?;
    let current = find(db, id).await?;
    let public = input.client_type == OauthClientType::Public;
    if public && !input.secret.is_empty() {
        return Err(ManagementError::Invalid("invalid_request"));
    }
    if !public && current.secret_hash.is_none() && input.secret.is_empty() {
        return Err(ManagementError::Invalid("secret_required"));
    }
    let changed = current.r#type != input.client_type
        || !input.secret.is_empty()
        || !same_set(&current.scopes, &input.scopes)
        || !same_set(&current.grant_types, &input.grant_types)
        || current.redirect_uris != input.redirect_uris
        || current.require_pkce != (input.require_pkce || public);
    let mut active: oauth_clients::ActiveModel = current.clone().into();
    if public || !input.secret.is_empty() {
        active.previous_secret_hash = Set(None);
        active.previous_secret_expires_at = Set(None);
    }
    if public {
        active.secret_hash = Set(None);
    } else if !input.secret.is_empty() {
        active.secret_hash = Set(Some(
            pero_utils::crypto::hash_secret_async(&input.secret).await?,
        ));
    }
    input.apply(&mut active);
    save_security_change(
        db,
        actor,
        P::ClientsManage,
        &current,
        active,
        changed.then_some("client_security_changed"),
    )
    .await?;
    Ok(())
}

fn same_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|value| right.contains(value))
}

pub async fn reset_secret(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
) -> Result<String, ManagementError> {
    let current = find(db, id).await?;
    if current.r#type == OauthClientType::Public {
        return Err(ManagementError::Invalid("invalid_client_type"));
    }
    let secret = pero_utils::crypto::generate_token();
    let mut active: oauth_clients::ActiveModel = current.clone().into();
    active.secret_hash = Set(Some(pero_utils::crypto::hash_secret_async(&secret).await?));
    active.previous_secret_hash = Set(None);
    active.previous_secret_expires_at = Set(None);
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    save_security_change(
        db,
        actor,
        P::ClientsSecretRotate,
        &current,
        active,
        Some("client_secret_reset"),
    )
    .await?;
    Ok(secret)
}

pub async fn toggle_status(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
) -> Result<(), ManagementError> {
    let current = find(db, id).await?;
    let mut active: oauth_clients::ActiveModel = current.clone().into();
    active.status = Set(match current.status {
        CommonStatus::Active => CommonStatus::Disabled,
        CommonStatus::Disabled => CommonStatus::Active,
    });
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    save_security_change(
        db,
        actor,
        P::ClientsManage,
        &current,
        active,
        Some("client_status_changed"),
    )
    .await?;
    Ok(())
}

/// Two credential slots allow a bounded deployment overlap without revoking user grants.
pub async fn rotate_secret(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
    grace_seconds: i64,
) -> Result<String, ManagementError> {
    if !(60..=604800).contains(&grace_seconds) {
        return Err(ManagementError::Invalid("invalid_request"));
    }
    let current = find(db, id).await?;
    if current.r#type != OauthClientType::Confidential {
        return Err(ManagementError::Invalid("invalid_client_type"));
    }
    if current
        .previous_secret_expires_at
        .is_some_and(|at| at > time::OffsetDateTime::now_utc())
    {
        return Err(ManagementError::Invalid("secret_rotation_pending"));
    }
    let secret = pero_utils::crypto::generate_token();
    let hash = pero_utils::crypto::hash_secret_async(&secret).await?;
    let mut active: oauth_clients::ActiveModel = current.clone().into();
    active.previous_secret_hash = Set(current.secret_hash.clone());
    active.previous_secret_expires_at = Set(Some(
        time::OffsetDateTime::now_utc() + time::Duration::seconds(grace_seconds),
    ));
    active.secret_hash = Set(Some(hash));
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    save_security_change(db, actor, P::ClientsSecretRotate, &current, active, None).await?;
    Ok(secret)
}
pub async fn retire_secret(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
) -> Result<(), ManagementError> {
    let current = find(db, id).await?;
    let mut active: oauth_clients::ActiveModel = current.clone().into();
    active.previous_secret_hash = Set(None);
    active.previous_secret_expires_at = Set(None);
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    save_security_change(db, actor, P::ClientsSecretRotate, &current, active, None).await?;
    Ok(())
}
