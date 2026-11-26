//! Registration and application admission share one verified-contact lifecycle.
use super::{ManagementError as Error, password::PasswordIdentityService, security::execute};
use crate::{
    db::{
        entity::{apps, identities, user_app_access, users},
        enums::{CommonStatus, UserStatus},
    },
    state::{app::AppState, session::SsoSession},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, QueryFilter, Statement,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
type Authorization = crate::db::entity::authorization_requests::Model;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct ApplicationSource {
    pub request_id: Uuid,
    pub app_id: Uuid,
    pub client_id: Uuid,
    pub tenant_id: Option<Uuid>,
}

impl From<&Authorization> for ApplicationSource {
    fn from(request: &Authorization) -> Self {
        Self {
            request_id: request.id,
            app_id: request.app_id,
            client_id: request.client_id,
            tenant_id: request.tenant_id,
        }
    }
}

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
    #[serde(default)]
    pub invitation_hash: Option<String>,
    #[serde(default)]
    pub enrollment_id: Option<Uuid>,
}
impl SocialProof {
    pub fn is_fresh(&self) -> bool {
        let age = OffsetDateTime::now_utc().unix_timestamp() - self.proved_at;
        (0..600).contains(&age)
    }
    pub(crate) fn matches(&self, row: &Enrollment) -> bool {
        self.is_fresh()
            && self.invitation_hash.is_none()
            && self.enrollment_id == Some(row.id)
            && self.app == row.app_id
            && row.provider_id == Some(self.provider)
            && row.subject.as_deref() == Some(self.subject.as_str())
    }
}

#[derive(Clone, Serialize, FromQueryResult)]
pub struct Enrollment {
    pub id: Uuid,
    pub app_id: Option<Uuid>,
    pub client_id: Option<Uuid>,
    pub auth_request_id: Option<Uuid>,
    pub email: Option<String>,
    pub phone: Option<String>,
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
    #[serde(skip)]
    pub requested_user_id: Option<Uuid>,
    #[serde(skip)]
    pub tenant_id: Option<Uuid>,
    #[serde(skip)]
    authorization_session_id: Option<Uuid>,
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
pub fn phone(value: &str) -> Result<String, Error> {
    let value = value.trim();
    if !value.starts_with('+')
        || !super::contact::ContactChannel::Phone.is_valid_format(value)
        || value.len() > 16
    {
        return Err(Error::Invalid("invalid_phone"));
    }
    Ok(value.to_owned())
}
fn eligible_phone(p: &Policy) -> Result<(), Error> {
    if p.emergency_stop || p.mode != "self_service" || !p.domains.is_empty() {
        return Err(Error::Invalid("registration_closed"));
    }
    Ok(())
}
fn contact(row: &Enrollment) -> Result<(&'static str, &str), Error> {
    row.email
        .as_deref()
        .map(|address| ("email", address))
        .or_else(|| row.phone.as_deref().map(|address| ("phone", address)))
        .ok_or_else(invalid)
}
pub async fn policy<C: ConnectionTrait>(db: &C, app: Option<Uuid>) -> Result<Policy, Error> {
    Policy::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT p.id,p.app_id,p.mode,p.domains,p.approval_required,platform.emergency_stop,p.version
         FROM registration_policies platform
         JOIN registration_policies p ON p.id=COALESCE(
             (SELECT id FROM registration_policies WHERE id=$1), platform.id)
         WHERE platform.id=$2 AND ($1::uuid IS NULL OR EXISTS (
             SELECT 1 FROM apps WHERE id=$1 AND NOT system AND status='active'))",
        [app.into(), Uuid::nil().into()],
    ))
    .one(db)
    .await?
    .ok_or_else(invalid)
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
    // Reconcile verified applications in both directions when the effective policy changes.
    let (from, to) = if effective.approval_required {
        ("ready", "pending_approval")
    } else {
        ("pending_approval", "ready")
    };
    execute(
        &txn,
        "UPDATE enrollments e SET status=$3 WHERE status=$2 AND NOT invitation AND approved_by IS NULL AND verified_at IS NOT NULL AND expires_at>now() AND (($1::uuid IS NULL AND (e.app_id IS NULL OR NOT EXISTS(SELECT 1 FROM registration_policies p WHERE p.app_id=e.app_id))) OR e.app_id=$1)",
        vec![input.app_id.into(), from.into(), to.into()],
    )
    .await?;
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
    let row = Enrollment::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT * FROM enrollments WHERE token_hash=$1",
        [pero_utils::crypto::sha256_hex(token).into()],
    ))
    .one(db)
    .await?
    .ok_or_else(invalid)?;
    Ok(with_expiry(row))
}

pub async fn progress<C: ConnectionTrait>(db: &C, id: Uuid) -> Result<Enrollment, Error> {
    Enrollment::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT * FROM enrollments WHERE id=$1",
        [id.into()],
    ))
    .one(db)
    .await?
    .map(with_expiry)
    .ok_or_else(invalid)
}

fn with_expiry(mut row: Enrollment) -> Enrollment {
    if row.expires_at <= OffsetDateTime::now_utc()
        && matches!(
            row.status.as_str(),
            "pending_verification" | "pending_approval" | "ready"
        )
    {
        row.status = "expired".into();
    }
    row
}

impl Enrollment {
    pub(crate) fn allows_browser_resend(&self, verified: bool) -> bool {
        !self.invitation
            && (self.status == "pending_verification"
                || (verified && matches!(self.status.as_str(), "pending_approval" | "ready")))
    }

    pub(crate) fn completed_result(&self, session: &SsoSession) -> Option<EnrollmentResult> {
        (self.status == "completed" && self.completed_user_id == Some(session.user_id))
            .then(|| self.result(session.user_id, None, Some(session), self.tenant_id))
    }

    fn result(
        &self,
        user_id: Uuid,
        identity: Option<identities::Model>,
        session: Option<&SsoSession>,
        tenant_id: Option<Uuid>,
    ) -> EnrollmentResult {
        EnrollmentResult {
            user_id,
            identity,
            app_id: self.app_id,
            client_id: self.client_id,
            auth_request_id: self.auth_request_id,
            resume_portal: session.is_some_and(|s| self.authorization_session_id == Some(s.id)),
            tenant_id,
        }
    }
}

pub(crate) async fn check<C: ConnectionTrait>(db: &C, row: &Enrollment) -> Result<Policy, Error> {
    let p = policy(db, row.app_id).await?;
    if !row.invitation {
        require_personal_app(db, row.app_id).await?;
    }
    if let Some(id) = row.provider_id {
        allow_social(db, id).await?;
    }
    if let Some(id) = row.requested_user_id
        && existing_account(db, row)
            .await?
            .is_none_or(|owner| owner.id != id || owner.status != UserStatus::Active)
    {
        return Err(Error::Invalid("enrollment_contact_changed"));
    }
    if let Some(email) = row.email.as_deref() {
        eligible(&p, email, row.invitation, row.domain_exception)?;
    } else {
        eligible_phone(&p)?;
    }
    if let Some(actor) = row.invited_by {
        let user = users::Entity::find_by_id(actor)
            .one(db)
            .await?
            .ok_or_else(invalid)?;
        if user.status != UserStatus::Active || user.deleted_at.is_some() {
            return Err(invalid());
        }
        let access = super::permissions::load(db, actor).await?;
        if !can_invite(&access, row.app_id, row.domain_exception) {
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

fn can_invite(access: &super::permissions::Access, app: Option<Uuid>, exception: bool) -> bool {
    access.super_admin
        || (app.is_none()
            && !exception
            && access.can_global(super::permissions::Permission::UsersCreate))
}
async fn send<C: ConnectionTrait>(
    db: &C,
    state: &AppState,
    id: Uuid,
    contact: (&str, &str),
    token: &str,
    expires: OffsetDateTime,
) -> Result<(), Error> {
    let (channel, address) = contact;
    if !state.config.notification.available(channel) {
        return Err(Error::Invalid("notification_disabled"));
    }
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(&state.config.sso.base_url, "sso/register");
    pero_utils::encode::append_query_param(&mut link, "token", token);
    super::notify::enqueue_enrollment(
        db,
        id,
        &super::notify::Notification {
            channel,
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
pub async fn invite(
    state: &AppState,
    address: &str,
    app: Option<Uuid>,
    actor: &SsoSession,
    exception: bool,
    reason: &str,
) -> Result<(), Error> {
    let address = email(address)?;
    start_contact(
        state,
        &address,
        app,
        false,
        StartKind::Invitation {
            actor,
            exception,
            reason,
        },
    )
    .await
    .map(|_| ())
}

pub(crate) async fn start_portal(
    state: &AppState,
    actor: &SsoSession,
    app: Uuid,
    source: Option<ApplicationSource>,
) -> Result<(), Error> {
    start_contact(
        state,
        "",
        Some(app),
        false,
        StartKind::Account { actor, source },
    )
    .await
    .map(|_| ())
}

pub async fn start_from_request(
    state: &AppState,
    address: &str,
    is_phone: bool,
    request: Option<&Authorization>,
    previous: Option<Uuid>,
) -> Result<Uuid, Error> {
    let address = if is_phone {
        phone(address)?
    } else {
        email(address)?
    };
    start_contact(
        state,
        &address,
        request.map(|request| request.app_id),
        is_phone,
        StartKind::SelfService {
            request,
            social: None,
            previous,
        },
    )
    .await?
    .ok_or_else(invalid)
}

enum StartKind<'a> {
    Invitation {
        actor: &'a SsoSession,
        exception: bool,
        reason: &'a str,
    },
    Account {
        actor: &'a SsoSession,
        source: Option<ApplicationSource>,
    },
    SelfService {
        request: Option<&'a Authorization>,
        social: Option<(Uuid, &'a str)>,
        previous: Option<Uuid>,
    },
}

async fn start_contact(
    state: &AppState,
    address: &str,
    app: Option<Uuid>,
    is_phone: bool,
    kind: StartKind<'_>,
) -> Result<Option<Uuid>, Error> {
    let limit_before_transaction = matches!(
        &kind,
        StartKind::Invitation { .. } | StartKind::SelfService { previous: None, .. }
    );
    if limit_before_transaction {
        limit_contact(state, address).await?;
    }
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let (invitation, source, social, account, previous) = match kind {
        StartKind::Invitation {
            actor,
            exception,
            reason,
        } => (Some((actor, exception, reason)), None, None, None, None),
        StartKind::Account { actor, source } => (None, source, None, Some(actor), None),
        StartKind::SelfService {
            request,
            social,
            previous,
        } => (
            None,
            request.map(ApplicationSource::from),
            social,
            None,
            previous,
        ),
    };
    let (client_id, request_id, tenant_id) = if let Some(source) = source {
        if Some(source.app_id) != app {
            return Err(invalid());
        }
        let current =
            crate::db::entity::authorization_requests::Entity::find_by_id(source.request_id)
                .one(&txn)
                .await?
                .filter(|current| {
                    current.client_id == source.client_id
                        && current.app_id == source.app_id
                        && current.diagnostic_session_id.is_none()
                });
        let active = current
            .as_ref()
            .filter(|r| r.completed_at.is_none() && r.expires_at > OffsetDateTime::now_utc());
        if account.is_none() {
            let request = active.ok_or(Error::Invalid("enrollment_request_expired"))?;
            if request.tenant_id.is_some() {
                return Err(Error::Invalid("enrollment_organization_required"));
            }
        }
        crate::db::entity::oauth_clients::Entity::find_by_id(source.client_id)
            .one(&txn)
            .await?
            .filter(|client| {
                client.status == CommonStatus::Active
                    && client.app_id == source.app_id
                    && client
                        .login_uri
                        .as_deref()
                        .is_some_and(super::client::valid_login_uri)
            })
            .ok_or_else(invalid)?;
        (
            Some(source.client_id),
            current.as_ref().map(|r| r.id),
            current.map_or(source.tenant_id, |r| r.tenant_id),
        )
    } else {
        (None, None, None)
    };
    let (invited, actor, exception, reason) = if let Some((actor, exception, reason)) = invitation {
        let access = super::permissions::authorize(
            &txn,
            &super::permissions::Actor {
                session: actor.clone(),
                idle_ttl_seconds: state.config.sso.session_idle_ttl_seconds,
            },
        )
        .await?;
        if !can_invite(&access, app, exception) || (!access.super_admin && !reason.is_empty()) {
            return Err(Error::Invalid("forbidden"));
        }
        if reason.len() > 500 || (exception && reason.trim().is_empty()) {
            return Err(Error::Invalid("invalid_request"));
        }
        (true, Some(actor.user_id), exception, reason)
    } else {
        (false, None, false, "")
    };
    if !invited {
        require_personal_app(&txn, app).await?;
    }
    if let Some((provider, _)) = social {
        allow_social(&txn, provider).await?;
    }
    let p = policy(&txn, app).await?;
    let account_contact = if let Some(actor) = account {
        let app_id = app.ok_or_else(invalid)?;
        if let Some(access) = user_app_access::Entity::find_by_id((actor.user_id, app_id))
            .one(&txn)
            .await?
        {
            if access.status != CommonStatus::Active {
                return Err(Error::Invalid("app_access_disabled"));
            }
            if access.admission_origin == "explicit" {
                return Ok(None);
            }
        }
        super::account_security::lock_account_session(&txn, actor, &state.config.sso).await?;
        if super::security::role(&txn, actor.user_id).await?.is_some() {
            return Err(Error::Invalid("forbidden"));
        }
        let user = users::Entity::find_by_id(actor.user_id)
            .one(&txn)
            .await?
            .ok_or_else(invalid)?;
        if p.emergency_stop || p.mode != "self_service" {
            return Err(Error::Invalid("registration_closed"));
        }
        let email = user
            .email
            .as_deref()
            .and_then(|v| email(v).ok())
            .filter(|v| {
                state.config.notification.available("email")
                    && eligible(&p, v, false, false).is_ok()
            });
        let phone = user
            .phone
            .as_deref()
            .and_then(|v| phone(v).ok())
            .filter(|_| state.config.notification.available("phone") && eligible_phone(&p).is_ok());
        Some(
            email
                .map(|v| (v, false))
                .or_else(|| phone.map(|v| (v, true)))
                .ok_or(Error::Invalid("enrollment_contact_required"))?,
        )
    } else {
        None
    };
    let (address, is_phone) = account_contact
        .as_ref()
        .map_or((address, is_phone), |(address, phone)| {
            (address.as_str(), *phone)
        });
    if is_phone {
        eligible_phone(&p)?;
    } else {
        eligible(&p, address, invited, exception)?;
    }
    let requested_user_id = account.map(|actor| actor.user_id);
    let authorization_session_id = account.filter(|_| source.is_some()).map(|actor| actor.id);
    let provider_id = social.map(|s| s.0);
    let subject = social.map(|s| s.1);
    if previous.is_some() || requested_user_id.is_some() {
        // An account's application survives a fresh OAuth request or session.
        // Keep its original continuation; other sessions use the client login URI.
        let existing = txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM enrollments WHERE NOT invitation AND (id=$1 OR requested_user_id=$2)
             AND requested_user_id IS NOT DISTINCT FROM $2::uuid AND app_id IS NOT DISTINCT FROM $3::uuid
             AND client_id IS NOT DISTINCT FROM $4::uuid
             AND provider_id IS NOT DISTINCT FROM $6::uuid AND subject IS NOT DISTINCT FROM $7::text
             AND (email=$8::citext OR phone=$9::citext) AND expires_at>now()
             AND tenant_id IS NOT DISTINCT FROM $10::uuid
             AND ($2::uuid IS NOT NULL OR (auth_request_id IS NOT DISTINCT FROM $5::uuid
                  AND authorization_session_id IS NOT DISTINCT FROM $11::uuid))
             AND status IN ('pending_verification','pending_approval','ready') ORDER BY created_at DESC LIMIT 1",
            [previous.into(), requested_user_id.into(), app.into(), client_id.into(), request_id.into(),
             provider_id.into(), subject.into(), (!is_phone).then_some(address).into(),
             is_phone.then_some(address).into(), tenant_id.into(), authorization_session_id.into()],
        )).await?;
        if let Some(row) = existing {
            return Ok(Some(row.try_get("", "id")?));
        }
    }
    if !limit_before_transaction {
        limit_contact(state, address).await?;
    }
    // Only invitations compete for the partial unique index. Periodic cleanup
    // handles all other expired enrollments outside this request transaction.
    if invited {
        let pending = txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM enrollments WHERE invitation AND email=$1::citext AND app_id IS NOT DISTINCT FROM $2::uuid
             AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",
            [address.into(), app.into()],
        )).await?;
        if pending.is_some() {
            return Err(Error::Invalid("enrollment_invitation_exists"));
        }
        execute(
            &txn,
            "UPDATE enrollments SET status='expired' WHERE invitation AND email=$1::citext AND app_id IS NOT DISTINCT FROM $2::uuid AND expires_at<=now() AND status IN ('pending_verification','pending_approval','ready')",
            vec![address.into(), app.into()],
        )
        .await?;
    }
    let token = pero_utils::crypto::generate_token();
    let id = Uuid::now_v7();
    let expiry = OffsetDateTime::now_utc() + time::Duration::hours(if invited { 72 } else { 24 });
    execute(&txn,"INSERT INTO enrollments(id,app_id,email,phone,invitation,invited_by,domain_exception,reason,token_hash,expires_at,client_id,auth_request_id,provider_id,subject,requested_user_id,tenant_id,authorization_session_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",vec![id.into(),app.into(),(!is_phone).then_some(address).into(),is_phone.then_some(address).into(),invited.into(),actor.into(),exception.into(),reason.into(),pero_utils::crypto::sha256_hex(&token).into(),expiry.into(),client_id.into(),request_id.into(),provider_id.into(),subject.into(),requested_user_id.into(),tenant_id.into(),authorization_session_id.into()]).await?;
    let channel = if is_phone { "phone" } else { "email" };
    send(&txn, state, id, (channel, address), &token, expiry).await?;
    txn.commit().await?;
    Ok(Some(id))
}
pub async fn verify(state: &AppState, token: &str) -> Result<Uuid, Error> {
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
    Ok(row.id)
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
                .zip(row.email.as_deref())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
                || own
                    .phone
                    .as_deref()
                    .zip(row.phone.as_deref())
                    .is_some_and(|(a, b)| a == b)
            {
                return Err(Error::Invalid("forbidden"));
            }
            if action == "approve" {
                check(&txn, &row).await?;
            }
            let token = pero_utils::crypto::generate_token();
            execute(&txn,"UPDATE enrollments SET status=$2,approved_by=$3,approved_at=now(),reason=$4,token_hash=$5,last_sent_at=now() WHERE id=$1",vec![id.into(),(if action=="approve" {"ready"} else {"rejected"}).into(),actor.user_id.into(),reason.into(),pero_utils::crypto::sha256_hex(&token).into()]).await?;
            cancel_notifications(&txn, id).await?;
            if action == "approve" {
                send(&txn, state, id, contact(&row)?, &token, row.expires_at).await?;
            } else {
                let mut link = pero_utils::oauth::url::issuer_endpoint(
                    &state.config.sso.base_url,
                    "sso/register",
                );
                pero_utils::encode::append_query_param(&mut link, "token", &token);
                let (channel, to) = contact(&row)?;
                super::notify::enqueue_enrollment(
                    &txn,
                    id,
                    &super::notify::Notification {
                        channel,
                        kind: "enrollment_rejected",
                        to,
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
        "resend" => {
            redeliver(&txn, state, &row, false).await?;
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

async fn rotate_token<C: ConnectionTrait>(db: &C, row: &Enrollment) -> Result<String, Error> {
    let token = pero_utils::crypto::generate_token();
    execute(
        db,
        "UPDATE enrollments SET token_hash=$2,last_sent_at=now() WHERE id=$1",
        vec![row.id.into(), pero_utils::crypto::sha256_hex(&token).into()],
    )
    .await?;
    cancel_notifications(db, row.id).await?;
    Ok(token)
}

async fn redeliver<C: ConnectionTrait>(
    db: &C,
    state: &AppState,
    row: &Enrollment,
    limit_recipient: bool,
) -> Result<(), Error> {
    if row.last_sent_at > OffsetDateTime::now_utc() - time::Duration::seconds(60) {
        return Err(Error::Invalid("rate_limited"));
    }
    check(db, row).await?;
    let contact = contact(row)?;
    if limit_recipient {
        limit_contact(state, contact.1).await?;
    }
    let token = rotate_token(db, row).await?;
    send(db, state, row.id, contact, &token, row.expires_at).await
}

pub(crate) async fn resend(state: &AppState, id: Uuid, verified: bool) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let row = progress(&txn, id).await?;
    if !row.allows_browser_resend(verified) {
        return Err(invalid());
    }
    redeliver(&txn, state, &row, true).await?;
    txn.commit().await?;
    Ok(())
}

pub(crate) async fn existing_account<C: ConnectionTrait>(
    db: &C,
    row: &Enrollment,
) -> Result<Option<users::Model>, Error> {
    let address = if let Some(email) = &row.email {
        users::Column::Email.eq(email.clone())
    } else {
        users::Column::Phone.eq(row.phone.clone().ok_or_else(invalid)?)
    };
    Ok(users::Entity::find()
        .filter(address)
        .filter(users::Column::DeletedAt.is_null())
        .one(db)
        .await?)
}

pub(crate) async fn already_admitted<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Option<Uuid>,
) -> Result<bool, Error> {
    let Some(app) = app else { return Ok(true) };
    Ok(user_app_access::Entity::find_by_id((user, app))
        .one(db)
        .await?
        .is_some_and(|access| has_explicit_access(&access)))
}

fn has_explicit_access(access: &user_app_access::Model) -> bool {
    access.status == CommonStatus::Active && access.admission_origin == "explicit"
}

pub struct EnrollmentResult {
    pub user_id: Uuid,
    pub identity: Option<identities::Model>,
    pub app_id: Option<Uuid>,
    pub client_id: Option<Uuid>,
    pub auth_request_id: Option<Uuid>,
    pub resume_portal: bool,
    pub tenant_id: Option<Uuid>,
}

pub async fn finalize(
    state: &AppState,
    token: &str,
    username: &str,
    password: &str,
    session: Option<&SsoSession>,
    social_proof: Option<&SocialProof>,
) -> Result<EnrollmentResult, Error> {
    let initial = lookup(&state.db, token).await?;
    if initial.verified_at.is_none() {
        return Err(Error::Invalid("approval_required"));
    }
    let existing = existing_account(&state.db, &initial).await?;
    let exists = existing.is_some();
    if !exists && requires_existing_account(&initial) {
        return Err(Error::Invalid("enrollment_contact_changed"));
    }
    if !exists && session.is_some() {
        return Err(Error::Invalid("enrollment_sign_out_required"));
    }
    if !exists && initial.status != "ready" {
        return Err(Error::Invalid("approval_required"));
    }
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
    let access = if let Some(app) = row.app_id {
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
                .await?
        } else {
            None
        }
    } else {
        None
    };
    let p = check(&txn, &row).await?;
    let existing = existing_account(&txn, &row).await?;
    if row
        .requested_user_id
        .is_some_and(|id| existing.as_ref().map(|u| u.id) != Some(id))
        || (existing.is_none() && requires_existing_account(&row))
    {
        return Err(Error::Invalid("enrollment_contact_changed"));
    }
    if row.verified_at.is_none() {
        return Err(Error::Invalid("approval_required"));
    }
    let existing_session = existing
        .as_ref()
        .map(|user| {
            session
                .filter(|s| s.user_id == user.id)
                .ok_or(Error::Invalid("existing_account_login_required"))
        })
        .transpose()?;
    let already_admitted = existing_session.is_some()
        && (row.app_id.is_none() || access.as_ref().is_some_and(has_explicit_access));
    if !already_admitted
        && (row.status != "ready"
            || (!row.invitation && p.approval_required && row.approved_by.is_none()))
    {
        return Err(Error::Invalid("approval_required"));
    }
    let mut identity = None;
    let user = if let Some(session) = existing_session {
        super::account_security::lock_account_session(&txn, session, &state.config.sso).await?;
        let user = users::Entity::find_by_id(session.user_id)
            .one(&txn)
            .await?
            .ok_or_else(invalid)?;
        let contact_matches = if let Some(email_address) = &row.email {
            user.email.as_deref().and_then(|v| email(v).ok()).as_deref()
                == Some(email_address.as_str())
        } else {
            user.phone.as_deref() == row.phone.as_deref()
        };
        if !contact_matches
            || user.status != UserStatus::Active
            || user.deleted_at.is_some()
            || super::security::role(&txn, user.id).await?.is_some()
        {
            return Err(invalid());
        }
        if row.email.is_some() && user.email_verified_at.is_none()
            || row.phone.is_some() && user.phone_verified_at.is_none()
        {
            execute(
                &txn,
                if row.email.is_some() {
                    "UPDATE users SET email_verified_at=now(),updated_at=now() WHERE id=$1"
                } else {
                    "UPDATE users SET phone_verified_at=now(),updated_at=now() WHERE id=$1"
                },
                vec![user.id.into()],
            )
            .await?;
        }
        user
    } else {
        if session.is_some() {
            return Err(Error::Invalid("enrollment_sign_out_required"));
        }
        use super::user::RegistrationCredential;
        let credential = if let Some(provider_id) = row.provider_id {
            if !social_proof.is_some_and(|proof| proof.matches(&row)) {
                return Err(Error::Invalid("social_reauthentication_required"));
            }
            RegistrationCredential::Social {
                provider_id,
                subject: row.subject.as_deref().ok_or_else(invalid)?,
            }
        } else {
            RegistrationCredential::Password(hash.ok_or_else(invalid)?)
        };
        let (user, created_identity) = super::user::create_verified_user(
            &txn,
            username,
            row.email.clone(),
            row.phone.clone(),
            credential,
        )
        .await?;
        identity = Some(created_identity);
        user
    };
    if let Some(app) = row.app_id
        && !access.as_ref().is_some_and(has_explicit_access)
    {
        let admitted = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO user_app_access(user_id,app_id) VALUES($1,$2)
                 ON CONFLICT (user_id,app_id) DO UPDATE
                 SET admission_origin='explicit',updated_at=now()
                 WHERE user_app_access.status='active'",
                [user.id.into(), app.into()],
            ))
            .await?;
        if admitted.rows_affected() == 0 {
            return Err(Error::Invalid("app_access_disabled"));
        }
    }
    // Only a newly created personal account has an implicit workspace choice.
    // Existing accounts retain the original OAuth tenant selection.
    let tenant_id = if row.client_id.is_some() && identity.is_some() {
        use crate::db::entity::tenants;
        tenants::Entity::find()
            .filter(tenants::Column::OwnerUserId.eq(user.id))
            .filter(tenants::Column::Kind.eq("personal"))
            .one(&txn)
            .await?
            .map(|tenant| tenant.id)
    } else {
        row.tenant_id
    };
    execute(
        &txn,
        "UPDATE enrollments SET status='completed',completed_user_id=$2,tenant_id=$3 WHERE id=$1",
        vec![row.id.into(), user.id.into(), tenant_id.into()],
    )
    .await?;
    cancel_notifications(&txn, row.id).await?;
    audit(&txn, &user, "enrollment_completed", row.id).await?;
    txn.commit().await?;
    Ok(row.result(user.id, identity, session, tenant_id))
}

pub(crate) fn requires_existing_account(row: &Enrollment) -> bool {
    row.requested_user_id.is_some()
        || (!row.invitation && row.app_id.is_some() && row.client_id.is_none())
}

pub async fn start_social(
    state: &AppState,
    address: &str,
    provider: Uuid,
    subject: &str,
    request: Option<&Authorization>,
    previous: Option<Uuid>,
) -> Result<Uuid, Error> {
    let address = email(address)?;
    start_contact(
        state,
        &address,
        request.map(|request| request.app_id),
        false,
        StartKind::SelfService {
            request,
            social: Some((provider, subject)),
            previous,
        },
    )
    .await?
    .ok_or_else(invalid)
}

async fn require_personal_app<C: ConnectionTrait>(db: &C, app: Option<Uuid>) -> Result<(), Error> {
    if let Some(app) = app
        && apps::Entity::find_by_id(app)
            .one(db)
            .await?
            .is_some_and(|app| app.tenant_mode == "organization")
    {
        return Err(Error::Invalid("enrollment_unavailable"));
    }
    Ok(())
}

async fn limit_contact(state: &AppState, address: &str) -> Result<(), Error> {
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
    let provider = super::provider::require_enabled_social(db, id)
        .await
        .map_err(|error| match error.kind() {
            pero_error::ErrorKind::Unauthorized => Error::Invalid("registration_closed"),
            _ => Error::from(error),
        })?;
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
    let phone = owner
        .filter(|u| u.phone_verified_at.is_some())
        .and_then(|u| u.phone.clone());
    let owner_id = owner.map(|u| u.id);
    let filter = "FROM (
        SELECT e.*, a.name AS app_name,
            CASE WHEN e.expires_at<=now() AND e.status IN ('pending_verification','pending_approval','ready')
                 THEN 'expired' ELSE e.status END AS effective_status
        FROM enrollments e LEFT JOIN apps a ON a.id=e.app_id
    ) e WHERE ($1 OR app_id=$2 OR ($2::uuid IS NULL AND app_id IS NULL))
      AND ($3::uuid IS NULL OR requested_user_id=$3 OR completed_user_id=$3
           OR (requested_user_id IS NULL AND completed_user_id IS NULL AND (email=$4::citext OR phone=$5::citext)))
      AND ($6='' OR strpos(lower(COALESCE(email::text,phone::text)),lower($6))>0 OR strpos(lower(COALESCE(app_name,'')),lower($6))>0)";
    let mut values: Vec<sea_orm::Value> = vec![
        (owner.is_some() || query.all_apps.unwrap_or(query.app.is_none())).into(),
        query.app.into(),
        owner_id.into(),
        address.into(),
        phone.into(),
        query.q.trim().into(),
    ];
    #[derive(FromQueryResult)]
    struct Counts {
        total: i64,
        pending: i64,
    }
    let counts=Counts::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT count(*) FILTER (WHERE $7='' OR effective_status=$7) AS total, count(*) FILTER (WHERE effective_status='pending_approval') AS pending {filter}"), {
        let mut v=values.clone(); v.push(query.status.clone().into()); v
    })).one(db).await?.ok_or_else(invalid)?;
    values.extend([
        query.status.clone().into(),
        (crate::config::DASHBOARD_PAGE_SIZE as i64).into(),
        (((page - 1) * crate::config::DASHBOARD_PAGE_SIZE) as i64).into(),
    ]);
    let rows=ProgressRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,format!("SELECT id,app_id,app_name,COALESCE(email::text,phone::text) AS email,invitation,effective_status AS status,reason,created_at,expires_at {filter} AND ($7='' OR effective_status=$7) ORDER BY (effective_status='pending_approval') DESC,created_at DESC,id DESC LIMIT $8 OFFSET $9"),values)).all(db).await?;
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
    let row=Enrollment::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT * FROM enrollments WHERE id=$1 AND (requested_user_id=$4 OR (requested_user_id IS NULL AND (email=$2::citext OR phone=$3::citext))) AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",[id.into(),user.email.clone().filter(|_| user.email_verified_at.is_some()).into(),user.phone.clone().filter(|_| user.phone_verified_at.is_some()).into(), user.id.into()])).one(&txn).await?.ok_or_else(invalid)?;
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
            let matches_verified = row.email.as_ref().is_some_and(|address| {
                user.email_verified_at.is_some()
                    && user
                        .email
                        .as_ref()
                        .is_some_and(|email| email.eq_ignore_ascii_case(address))
            }) || row.phone.as_ref().is_some_and(|number| {
                user.phone_verified_at.is_some() && user.phone.as_ref() == Some(number)
            });
            if action == "resend" || !matches_verified {
                redeliver(&txn, state, &row, false).await?;
                None
            } else {
                check(&txn, &row).await?;
                Some(rotate_token(&txn, &row).await?)
            }
        }
        _ => return Err(Error::Invalid("invalid_request")),
    };
    audit(&txn, &user, &format!("enrollment_{action}"), id).await?;
    txn.commit().await?;
    Ok(token)
}
