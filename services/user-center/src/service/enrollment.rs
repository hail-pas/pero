//! Registration and application admission share one email-proved request lifecycle.
use super::{ManagementError as Error, password::PasswordIdentityService, security::execute};
use crate::{
    db::{
        entity::{apps, identities, user_app_access, users},
        enums::{CommonStatus, IdentityKind, UserStatus},
    },
    state::{app::AppState, session::SsoSession},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, FromQueryResult,
    QueryFilter, Set, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, FromQueryResult)]
pub struct Policy {
    pub id: Uuid,
    pub app_id: Option<Uuid>,
    pub mode: String,
    pub domains: Vec<String>,
    pub approval_required: bool,
    pub emergency_stop: bool,
    pub version: i64,
}
/// A fresh provider callback, authenticated by the browser's signed HttpOnly cookie.
#[derive(Serialize, Deserialize)]
pub struct SocialProof {
    pub provider: Uuid,
    pub subject: String,
    pub proved_at: i64,
    pub app: Option<Uuid>,
}
impl SocialProof {
    pub fn is_fresh(&self) -> bool {
        let age = OffsetDateTime::now_utc().unix_timestamp() - self.proved_at;
        (0..600).contains(&age)
    }
    fn matches(&self, row: &Enrollment) -> bool {
        self.is_fresh()
            && row.provider_id == Some(self.provider)
            && row.subject.as_deref() == Some(self.subject.as_str())
    }
}

#[derive(Clone, Serialize, FromQueryResult)]
pub struct Enrollment {
    pub id: Uuid,
    pub app_id: Option<Uuid>,
    pub email: String,
    pub invitation: bool,
    pub invited_by: Option<Uuid>,
    pub domain_exception: bool,
    pub reason: String,
    #[serde(skip)]
    pub token_hash: String,
    pub status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub verified_at: Option<OffsetDateTime>,
    pub approved_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub approved_at: Option<OffsetDateTime>,
    pub provider_id: Option<Uuid>,
    #[serde(skip)]
    pub subject: Option<String>,
    pub completed_user_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_sent_at: OffsetDateTime,
}
fn invalid() -> Error {
    Error::Invalid("enrollment_unavailable")
}
pub fn email(value: &str) -> Result<String, Error> {
    let value = value.trim();
    if !validator::ValidateEmail::validate_email(&value) || value.len() > 254 {
        return Err(Error::Invalid("invalid_email"));
    }
    let (local, domain) = value.rsplit_once('@').ok_or_else(invalid)?;
    let domain = url::Host::parse(domain)
        .map_err(|_| Error::Invalid("invalid_email"))?
        .to_string();
    Ok(format!(
        "{}@{}",
        local.to_lowercase(),
        domain.to_lowercase()
    ))
}
pub async fn policy<C: ConnectionTrait>(db: &C, app: Option<Uuid>) -> Result<Policy, Error> {
    if let Some(id) = app {
        let app = apps::Entity::find_by_id(id)
            .one(db)
            .await?
            .ok_or_else(invalid)?;
        if app.system || app.status != CommonStatus::Active {
            return Err(invalid());
        }
    }
    let platform = Policy::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT * FROM registration_policies WHERE id=$1",
        [Uuid::nil().into()],
    ))
    .one(db)
    .await?
    .ok_or_else(invalid)?;
    let mut result = if let Some(id) = app {
        Policy::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT * FROM registration_policies WHERE id=$1",
            [id.into()],
        ))
        .one(db)
        .await?
        .unwrap_or(platform.clone())
    } else {
        platform.clone()
    };
    result.emergency_stop = platform.emergency_stop;
    Ok(result)
}
fn eligible(p: &Policy, address: &str, invited: bool, exception: bool) -> Result<(), Error> {
    if p.emergency_stop || p.mode == "closed" || (!invited && p.mode != "self_service") {
        return Err(Error::Invalid("registration_closed"));
    }
    let domain = address.rsplit_once('@').ok_or_else(invalid)?.1;
    if !exception && !p.domains.is_empty() && !p.domains.iter().any(|d| d == domain) {
        return Err(Error::Invalid("email_domain_not_allowed"));
    }
    Ok(())
}
pub async fn require_admin<C: ConnectionTrait>(
    db: &C,
    actor: &SsoSession,
    state: &AppState,
) -> Result<(), Error> {
    let user = users::Entity::find_by_id(actor.user_id)
        .one(db)
        .await?
        .ok_or_else(invalid)?;
    if user.status != UserStatus::Active
        || user.deleted_at.is_some()
        || super::security::role(db, user.id).await?.as_deref() != Some("super_admin")
        || !super::security::recent(db, actor.id, state.config.sso.session_idle_ttl_seconds).await?
    {
        return Err(Error::Invalid("forbidden"));
    }
    Ok(())
}
pub async fn save_policy(
    state: &AppState,
    actor: &SsoSession,
    mut input: Policy,
    inherit: bool,
) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    require_admin(&txn, actor, state).await?;
    policy(&txn, input.app_id).await?;
    input.id = input.app_id.unwrap_or(Uuid::nil());
    if inherit && input.app_id.is_some() {
        execute(
            &txn,
            "DELETE FROM registration_policies WHERE id=$1",
            vec![input.id.into()],
        )
        .await?;
    } else {
        if !matches!(
            input.mode.as_str(),
            "closed" | "invite_only" | "self_service"
        ) || input.domains.len() > 100
        {
            return Err(Error::Invalid("invalid_request"));
        }
        input.domains = input
            .domains
            .iter()
            .map(|d| {
                email(&format!("x@{}", d.trim())).map(|v| v.split_once('@').unwrap().1.to_owned())
            })
            .collect::<Result<_, _>>()?;
        let count=txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,"INSERT INTO registration_policies(id,app_id,mode,domains,approval_required,emergency_stop) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET mode=$3,domains=$4,approval_required=$5,emergency_stop=$6,version=registration_policies.version+1 WHERE registration_policies.version=$7",[input.id.into(),input.app_id.into(),input.mode.into(),input.domains.into(),input.approval_required.into(),(input.app_id.is_none() && input.emergency_stop).into(),input.version.into()])).await?.rows_affected();
        if count == 0 {
            return Err(Error::Invalid("policy_conflict"));
        }
    }
    let effective = policy(&txn, input.app_id).await?;
    if effective.approval_required {
        execute(&txn,"UPDATE enrollments e SET status='pending_approval' WHERE status='ready' AND NOT invitation AND approved_by IS NULL AND (($1::uuid IS NULL AND (e.app_id IS NULL OR NOT EXISTS(SELECT 1 FROM registration_policies p WHERE p.app_id=e.app_id))) OR e.app_id=$1)",vec![input.app_id.into()]).await?;
    }
    txn.commit().await?;
    Ok(())
}
pub async fn lookup<C: ConnectionTrait>(db: &C, token: &str) -> Result<Enrollment, Error> {
    if token.len() != 43 {
        return Err(invalid());
    }
    Enrollment::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT * FROM enrollments WHERE token_hash=$1 AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",[pero_utils::crypto::sha256_hex(token).into()])).one(db).await?.ok_or_else(invalid)
}
/// Read-only progress remains available after a decision; mutations still use lookup().
pub async fn progress_by_token<C: ConnectionTrait>(
    db: &C,
    token: &str,
) -> Result<Enrollment, Error> {
    if token.len() != 43 {
        return Err(invalid());
    }
    let mut row = Enrollment::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT * FROM enrollments WHERE token_hash=$1",
        [pero_utils::crypto::sha256_hex(token).into()],
    ))
    .one(db)
    .await?
    .ok_or_else(invalid)?;
    if row.expires_at <= OffsetDateTime::now_utc()
        && matches!(
            row.status.as_str(),
            "pending_verification" | "pending_approval" | "ready"
        )
    {
        row.status = "expired".into();
    }
    Ok(row)
}
async fn check<C: ConnectionTrait>(db: &C, row: &Enrollment) -> Result<Policy, Error> {
    let p = policy(db, row.app_id).await?;
    if let Some(id) = row.provider_id {
        allow_social(db, id).await?;
    }
    eligible(&p, &row.email, row.invitation, row.domain_exception)?;
    if let Some(actor) = row.invited_by {
        let user = users::Entity::find_by_id(actor)
            .one(db)
            .await?
            .ok_or_else(invalid)?;
        if user.status != UserStatus::Active
            || user.deleted_at.is_some()
            || super::security::role(db, actor).await?.as_deref() != Some("super_admin")
        {
            return Err(invalid());
        }
    }
    if let Some(actor) = row.approved_by
        && super::security::role(db, actor).await?.as_deref() != Some("super_admin")
    {
        return Err(Error::Invalid("approval_required"));
    }
    Ok(p)
}
async fn send<C: ConnectionTrait>(
    db: &C,
    state: &AppState,
    id: Uuid,
    address: &str,
    token: &str,
    expires: OffsetDateTime,
) -> Result<(), Error> {
    if state.config.notification.endpoint.is_empty() {
        return Err(Error::Invalid("notification_disabled"));
    }
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(&state.config.sso.base_url, "sso/register");
    pero_utils::encode::append_query_param(&mut link, "token", token);
    super::notify::enqueue_enrollment(
        db,
        id,
        &super::notify::Notification {
            channel: "email",
            kind: "enrollment",
            to: address,
            code: None,
            link: &link,
        },
        expires,
    )
    .await?;
    Ok(())
}
pub async fn start(
    state: &AppState,
    address: &str,
    app: Option<Uuid>,
    invitation: Option<(&SsoSession, bool, &str)>,
) -> Result<(), Error> {
    let address = email(address)?;
    limit_email(state, &address).await?;
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let (invited, actor, exception, reason) = if let Some((actor, exception, reason)) = invitation {
        require_admin(&txn, actor, state).await?;
        if reason.len() > 500 || (exception && reason.trim().is_empty()) {
            return Err(Error::Invalid("invalid_request"));
        }
        (true, Some(actor.user_id), exception, reason)
    } else {
        (false, None, false, "")
    };
    eligible(&policy(&txn, app).await?, &address, invited, exception)?;
    execute(&txn,"UPDATE enrollments SET status='expired' WHERE expires_at<=now() AND status IN ('pending_verification','pending_approval','ready')",vec![]).await?;
    let token = pero_utils::crypto::generate_token();
    let id = Uuid::now_v7();
    let expiry = OffsetDateTime::now_utc() + time::Duration::hours(if invited { 72 } else { 24 });
    execute(&txn,"INSERT INTO enrollments(id,app_id,email,invitation,invited_by,domain_exception,reason,token_hash,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",vec![id.into(),app.into(),address.clone().into(),invited.into(),actor.into(),exception.into(),reason.into(),pero_utils::crypto::sha256_hex(&token).into(),expiry.into()]).await?;
    send(&txn, state, id, &address, &token, expiry).await?;
    txn.commit().await?;
    Ok(())
}
pub async fn verify(state: &AppState, token: &str) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let row = lookup(&txn, token).await?;
    let p = check(&txn, &row).await?;
    if row.status == "pending_verification" {
        let status = if !row.invitation && p.approval_required {
            "pending_approval"
        } else {
            "ready"
        };
        execute(
            &txn,
            "UPDATE enrollments SET status=$2,verified_at=now() WHERE id=$1",
            vec![row.id.into(), status.into()],
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}
pub async fn manage(
    state: &AppState,
    actor: &SsoSession,
    id: Uuid,
    action: &str,
    reason: &str,
) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    require_admin(&txn, actor, state).await?;
    let row=Enrollment::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT * FROM enrollments WHERE id=$1 AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",[id.into()])).one(&txn).await?.ok_or_else(invalid)?;
    if reason.len() > 500 {
        return Err(Error::Invalid("invalid_request"));
    }
    match action {
        "approve" | "reject" if row.status == "pending_approval" => {
            let own = users::Entity::find_by_id(actor.user_id)
                .one(&txn)
                .await?
                .ok_or_else(invalid)?;
            if own
                .email
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(&row.email))
            {
                return Err(Error::Invalid("forbidden"));
            }
            let token = pero_utils::crypto::generate_token();
            execute(&txn,"UPDATE enrollments SET status=$2,approved_by=$3,approved_at=now(),reason=$4,token_hash=$5,last_sent_at=now() WHERE id=$1",vec![id.into(),(if action=="approve" {"ready"} else {"rejected"}).into(),actor.user_id.into(),reason.into(),pero_utils::crypto::sha256_hex(&token).into()]).await?;
            cancel_notifications(&txn, id).await?;
            if action == "approve" {
                send(&txn, state, id, &row.email, &token, row.expires_at).await?;
            } else {
                let mut link = pero_utils::oauth::url::issuer_endpoint(
                    &state.config.sso.base_url,
                    "sso/register",
                );
                pero_utils::encode::append_query_param(&mut link, "token", &token);
                super::notify::enqueue_enrollment(
                    &txn,
                    id,
                    &super::notify::Notification {
                        channel: "email",
                        kind: "enrollment_rejected",
                        to: &row.email,
                        code: None,
                        link: &link,
                    },
                    row.expires_at,
                )
                .await?;
            }
        }
        "revoke" => {
            execute(
                &txn,
                "UPDATE enrollments SET status='revoked' WHERE id=$1",
                vec![id.into()],
            )
            .await?;
            cancel_notifications(&txn, id).await?;
        }
        "resend" if row.last_sent_at < OffsetDateTime::now_utc() - time::Duration::seconds(60) => {
            check(&txn, &row).await?;
            let token = pero_utils::crypto::generate_token();
            execute(
                &txn,
                "UPDATE enrollments SET token_hash=$2,last_sent_at=now() WHERE id=$1",
                vec![id.into(), pero_utils::crypto::sha256_hex(&token).into()],
            )
            .await?;
            cancel_notifications(&txn, id).await?;
            send(&txn, state, id, &row.email, &token, row.expires_at).await?;
        }
        _ => return Err(invalid()),
    }
    txn.commit().await?;
    Ok(())
}
async fn cancel_notifications<C: ConnectionTrait>(db: &C, id: Uuid) -> Result<(), Error> {
    execute(
        db,
        "DELETE FROM notification_outbox WHERE enrollment_id=$1",
        vec![id.into()],
    )
    .await?;
    Ok(())
}

pub async fn finalize(
    state: &AppState,
    token: &str,
    username: &str,
    password: &str,
    session: Option<&SsoSession>,
    social_proof: Option<&SocialProof>,
) -> Result<(), Error> {
    let initial = lookup(&state.db, token).await?;
    let exists = users::Entity::find()
        .filter(users::Column::Email.eq(initial.email.clone()))
        .one(&state.db)
        .await?
        .is_some();
    if !exists {
        crate::db::helper::user::validate_username(username.trim()).map_err(Error::Validation)?;
    }
    let hash = if !exists && initial.provider_id.is_none() {
        state
            .config
            .password
            .validate_password(password)
            .map_err(Error::Validation)?;
        Some(PasswordIdentityService::hash_password(password).await?)
    } else {
        None
    };
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let row = lookup(&txn, token).await?;
    let p = check(&txn, &row).await?;
    if row.status != "ready"
        || row.verified_at.is_none()
        || (!row.invitation && p.approval_required && row.approved_by.is_none())
    {
        return Err(Error::Invalid("approval_required"));
    }
    if let Some(app) = row.app_id {
        use sea_orm::QuerySelect;
        apps::Entity::find_by_id(app)
            .lock_shared()
            .one(&txn)
            .await?
            .ok_or_else(invalid)?;
        if let Some(session) = session {
            user_app_access::Entity::find_by_id((session.user_id, app))
                .lock_exclusive()
                .one(&txn)
                .await?;
        }
    }
    let now = OffsetDateTime::now_utc();
    let existing = users::Entity::find()
        .filter(users::Column::Email.eq(row.email.clone()))
        .one(&txn)
        .await?;
    let user = if let Some(user) = existing {
        let session = session
            .filter(|s| s.user_id == user.id)
            .ok_or(Error::Invalid("existing_account_login_required"))?;
        super::account_security::lock_account_session(&txn, session, &state.config.sso).await?;
        let user = users::Entity::find_by_id(user.id)
            .one(&txn)
            .await?
            .ok_or_else(invalid)?;
        if user.email.as_deref().and_then(|v| email(v).ok()).as_deref() != Some(&row.email)
            || user.status != UserStatus::Active
            || user.deleted_at.is_some()
            || super::security::role(&txn, user.id).await?.is_some()
        {
            return Err(invalid());
        }
        if user.email_verified_at.is_none() {
            execute(
                &txn,
                "UPDATE users SET email_verified_at=now(),updated_at=now() WHERE id=$1",
                vec![user.id.into()],
            )
            .await?;
        }
        user
    } else {
        let user = users::ActiveModel {
            id: Set(Uuid::now_v7()),
            username: Set(username.trim().to_owned()),
            email: Set(Some(row.email.clone())),
            email_verified_at: Set(Some(now)),
            status: Set(UserStatus::Active),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(&txn)
        .await?;
        if let Some(provider_id) = row.provider_id {
            super::provider::require_enabled_social(&txn, provider_id).await?;
            if !social_proof.is_some_and(|proof| proof.matches(&row)) {
                return Err(Error::Invalid("social_reauthentication_required"));
            }
            identities::ActiveModel {
                id: Set(Uuid::now_v7()),
                user_id: Set(user.id),
                provider_id: Set(provider_id),
                kind: Set(IdentityKind::Oauth),
                subject: Set(row.subject.clone().ok_or_else(invalid)?),
                profile: Set(serde_json::json!({})),
                created_at: Set(now),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(&txn)
            .await?;
        } else {
            let provider = crate::db::helper::identity_provider::find_local_provider(&txn).await?;
            PasswordIdentityService::create_hashed(
                &txn,
                user.id,
                provider.id,
                user.id.to_string(),
                hash.ok_or_else(invalid)?,
                now,
            )
            .await?;
        }
        user
    };
    if let Some(app) = row.app_id {
        let existing = user_app_access::Entity::find_by_id((user.id, app))
            .one(&txn)
            .await?;
        if existing
            .as_ref()
            .is_some_and(|a| a.status != CommonStatus::Active)
        {
            return Err(Error::Invalid("app_access_disabled"));
        }
        if existing.is_none() {
            user_app_access::ActiveModel {
                user_id: Set(user.id),
                app_id: Set(app),
                status: Set(CommonStatus::Active),
                created_at: Set(now),
                updated_at: Set(now),
                ..Default::default()
            }
            .insert(&txn)
            .await?;
        }
    }
    execute(
        &txn,
        "UPDATE enrollments SET status='completed',completed_user_id=$2 WHERE id=$1",
        vec![row.id.into(), user.id.into()],
    )
    .await?;
    cancel_notifications(&txn, row.id).await?;
    audit(&txn, &user, "enrollment_completed", row.id).await?;
    txn.commit().await?;
    Ok(())
}

pub async fn start_social(
    state: &AppState,
    address: &str,
    app: Option<Uuid>,
    provider: Uuid,
    subject: &str,
) -> Result<(), Error> {
    // Reuse the same delivery and admission path; persist upstream identity before delivery.
    limit_email(state, address).await?;
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    eligible(&policy(&txn, app).await?, address, false, false)?;
    allow_social(&txn, provider).await?;
    let id = Uuid::now_v7();
    let token = pero_utils::crypto::generate_token();
    let expiry = OffsetDateTime::now_utc() + time::Duration::hours(24);
    execute(&txn,"INSERT INTO enrollments(id,app_id,email,token_hash,expires_at,provider_id,subject) VALUES($1,$2,$3,$4,$5,$6,$7)",vec![id.into(),app.into(),address.into(),pero_utils::crypto::sha256_hex(&token).into(),expiry.into(),provider.into(),subject.into()]).await?;
    send(&txn, state, id, address, &token, expiry).await?;
    txn.commit().await?;
    Ok(())
}

async fn limit_email(state: &AppState, address: &str) -> Result<(), Error> {
    let hash = pero_utils::crypto::hmac_sha256(
        address.as_bytes(),
        state
            .config
            .sso
            .cookie_signing_secret
            .expose_secret()
            .as_bytes(),
    );
    let key = pero_cache_redis::rate_limit_key::rl_enrollment_email.key(&hash)?;
    match pero_cache_redis::enforce_rate_limit(&state.cache, &key, 3).await {
        Ok(()) => Ok(()),
        Err(pero_cache_redis::RateLimitError::Denied { .. }) => Err(Error::Invalid("rate_limited")),
        Err(pero_cache_redis::RateLimitError::Redis(e)) => Err(Error::Credential(e)),
    }
}
pub async fn allow_social<C: ConnectionTrait>(db: &C, id: Uuid) -> Result<(), Error> {
    super::provider::require_enabled_social(db, id).await?;
    let provider = crate::db::entity::identity_providers::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or_else(invalid)?;
    if provider
        .settings
        .get("allow_registration")
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return Err(Error::Invalid("registration_closed"));
    }
    Ok(())
}

pub async fn invalidate_sponsor<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
) -> Result<(), sea_orm::DbErr> {
    execute(db,"DELETE FROM notification_outbox WHERE enrollment_id IN (SELECT id FROM enrollments WHERE (invited_by=$1 OR approved_by=$1) AND status IN ('pending_verification','pending_approval','ready'))",vec![user.into()]).await?;
    execute(db,"UPDATE enrollments SET status='revoked' WHERE (invited_by=$1 OR approved_by=$1) AND status IN ('pending_verification','pending_approval','ready')",vec![user.into()]).await
}
async fn audit<C: ConnectionTrait>(
    db: &C,
    user: &users::Model,
    action: &str,
    target: Uuid,
) -> Result<(), Error> {
    execute(db,"INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) VALUES($1,$2,$3,$4,'success',200)",vec![user.id.into(),user.username.clone().into(),action.into(),target.to_string().into()]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_domain_and_independent_modes() {
        let mut p = Policy {
            id: Uuid::nil(),
            app_id: None,
            mode: "self_service".into(),
            domains: vec!["example.com".into()],
            approval_required: true,
            emergency_stop: false,
            version: 1,
        };
        assert!(eligible(&p, "a@example.com", false, false).is_ok());
        assert!(eligible(&p, "a@sub.example.com", false, false).is_err());
        p.mode = "invite_only".into();
        assert!(eligible(&p, "a@example.com", false, false).is_err());
        assert!(eligible(&p, "a@external.com", true, true).is_ok());
        p.emergency_stop = true;
        assert!(eligible(&p, "a@example.com", true, false).is_err());
    }
}

/// The same filtered query drives the approval desk and the owner's progress list.
#[derive(Default, Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub status: String,
    pub app: Option<Uuid>,
    #[serde(default)]
    pub all_apps: Option<bool>,
}
#[derive(Serialize, FromQueryResult)]
pub struct ProgressRow {
    pub id: Uuid,
    pub app_id: Option<Uuid>,
    pub app_name: Option<String>,
    pub email: String,
    pub invitation: bool,
    pub status: String,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}
#[derive(Serialize)]
pub struct ProgressList {
    pub rows: Vec<ProgressRow>,
    pub page: u64,
    pub total_pages: u64,
    pub pending_count: i64,
}
pub async fn list(
    db: &sea_orm::DatabaseConnection,
    query: &ListQuery,
    owner: Option<&users::Model>,
) -> Result<ProgressList, Error> {
    if !query.status.is_empty()
        && !matches!(
            query.status.as_str(),
            "pending_verification"
                | "pending_approval"
                | "ready"
                | "completed"
                | "rejected"
                | "revoked"
                | "expired"
        )
    {
        return Err(Error::Invalid("invalid_request"));
    }
    let page = query.page.unwrap_or(1).clamp(1, 1_000_000);
    let address = owner
        .filter(|u| u.email_verified_at.is_some())
        .and_then(|u| u.email.clone());
    let owner_id = owner.map(|u| u.id);
    let filter = "FROM (SELECT e.*, a.name AS app_name, CASE WHEN e.expires_at<=now() AND e.status IN ('pending_verification','pending_approval','ready') THEN 'expired' ELSE e.status END AS effective_status FROM enrollments e LEFT JOIN apps a ON a.id=e.app_id) e WHERE ($1 OR app_id IS NOT DISTINCT FROM $2) AND ($3::uuid IS NULL OR completed_user_id=$3 OR email=$4::citext) AND ($5='' OR strpos(lower(email::text),lower($5))>0 OR strpos(lower(COALESCE(app_name,'')),lower($5))>0)";
    let mut values: Vec<sea_orm::Value> = vec![
        (owner.is_some() || query.all_apps.unwrap_or(query.app.is_none())).into(),
        query.app.into(),
        owner_id.into(),
        address.into(),
        query.q.trim().into(),
    ];
    #[derive(FromQueryResult)]
    struct Counts {
        total: i64,
        pending: i64,
    }
    let counts=Counts::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT count(*) FILTER (WHERE $6='' OR effective_status=$6) AS total, count(*) FILTER (WHERE effective_status='pending_approval') AS pending {filter}"), {
        let mut v=values.clone(); v.push(query.status.clone().into()); v
    })).one(db).await?.ok_or_else(invalid)?;
    values.extend([
        query.status.clone().into(),
        (crate::config::DASHBOARD_PAGE_SIZE as i64).into(),
        (((page - 1) * crate::config::DASHBOARD_PAGE_SIZE) as i64).into(),
    ]);
    let rows=ProgressRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT id,app_id,app_name,email::text,invitation,effective_status AS status,reason,created_at,expires_at {filter} AND ($6='' OR effective_status=$6) ORDER BY (effective_status='pending_approval') DESC,created_at DESC,id DESC LIMIT $7 OFFSET $8"),values)).all(db).await?;
    Ok(ProgressList {
        rows,
        page,
        total_pages: (counts.total as u64).div_ceil(crate::config::DASHBOARD_PAGE_SIZE),
        pending_count: counts.pending,
    })
}

/// Never disclose or resume an invitation using an unverified account address.
pub async fn owner_action(
    state: &AppState,
    actor: &SsoSession,
    id: Uuid,
    action: &str,
) -> Result<Option<String>, Error> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    super::account_security::lock_account_session(&txn, actor, &state.config.sso).await?;
    let user = users::Entity::find_by_id(actor.user_id)
        .one(&txn)
        .await?
        .ok_or_else(invalid)?;
    let row=Enrollment::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT * FROM enrollments WHERE id=$1 AND email=$2::citext AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",[id.into(),user.email.clone().filter(|_| user.email_verified_at.is_some()).into()])).one(&txn).await?.ok_or_else(invalid)?;
    let token = match action {
        "withdraw" => {
            execute(
                &txn,
                "UPDATE enrollments SET status='revoked' WHERE id=$1",
                vec![id.into()],
            )
            .await?;
            cancel_notifications(&txn, id).await?;
            None
        }
        "continue" | "resend" => {
            check(&txn, &row).await?;
            if action == "resend"
                && row.last_sent_at > OffsetDateTime::now_utc() - time::Duration::seconds(60)
            {
                return Err(Error::Invalid("rate_limited"));
            }
            let token = pero_utils::crypto::generate_token();
            execute(
                &txn,
                "UPDATE enrollments SET token_hash=$2,last_sent_at=now() WHERE id=$1",
                vec![id.into(), pero_utils::crypto::sha256_hex(&token).into()],
            )
            .await?;
            cancel_notifications(&txn, id).await?;
            if action == "resend" {
                send(&txn, state, id, &row.email, &token, row.expires_at).await?;
                None
            } else {
                Some(token)
            }
        }
        _ => return Err(Error::Invalid("invalid_request")),
    };
    audit(&txn, &user, &format!("enrollment_{action}"), id).await?;
    txn.commit().await?;
    Ok(token)
}
