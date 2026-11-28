//! Account registration and invitations with contact verification where required.
use super::{
    ManagementError as Error, password::PasswordIdentityService, permissions, security::execute,
};
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
    pub app_id: Option<Uuid>,
    pub mode: String,
    pub domains: Vec<String>,
    pub approval_required: bool,
    pub emergency_stop: bool,
    pub version: i64,
}

impl Policy {
    pub(crate) fn invitations_open(&self) -> bool {
        !self.emergency_stop && self.mode != "closed"
    }
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

#[derive(FromQueryResult)]
pub struct Enrollment {
    pub id: Uuid,
    pub app_id: Option<Uuid>,
    pub client_id: Option<Uuid>,
    pub auth_request_id: Option<Uuid>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub invitation: bool,
    pub invited_by: Option<Uuid>,
    pub(crate) manual_delivery: bool,
    pub domain_exception: bool,
    pub reason: String,
    pub status: String,
    pub verified_at: Option<OffsetDateTime>,
    pub approved_by: Option<Uuid>,
    pub provider_id: Option<Uuid>,
    pub subject: Option<String>,
    pub completed_user_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
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
        "SELECT p.app_id, COALESCE(p.mode, platform.mode) AS mode,
                COALESCE(p.domains, platform.domains) AS domains,
                COALESCE(p.approval_required, platform.approval_required) AS approval_required,
                platform.emergency_stop, COALESCE(p.version, platform.version) AS version
         FROM registration_policies platform
         LEFT JOIN registration_policies p ON p.app_id=$1
         WHERE platform.app_id IS NULL AND ($1::uuid IS NULL OR EXISTS (
             SELECT 1 FROM apps WHERE id=$1 AND NOT system AND status='active'))",
        [app.into()],
    ))
    .one(db)
    .await?
    .ok_or_else(invalid)
}
pub(super) fn email_domain_allowed(domains: &[String], address: &str) -> bool {
    address
        .rsplit_once('@')
        .and_then(|(_, domain)| url::Host::parse(domain).ok())
        .is_some_and(|host| domains.contains(&host.to_string()))
}

fn eligible(
    p: &Policy,
    address: Option<&str>,
    invited: bool,
    exception: bool,
) -> Result<(), Error> {
    if !p.invitations_open() || (!invited && p.mode != "self_service") {
        return Err(Error::Invalid("registration_closed"));
    }
    if !exception
        && !p.domains.is_empty()
        && !address.is_some_and(|address| email_domain_allowed(&p.domains, address))
    {
        return Err(Error::Invalid("email_domain_not_allowed"));
    }
    Ok(())
}
pub async fn save_policy(
    state: &AppState,
    actor: &permissions::Actor,
    mut input: Policy,
    inherit: bool,
) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    permissions::require_super(&txn, actor).await?;
    let current = policy(&txn, input.app_id).await?;
    if current.version != input.version {
        return Err(Error::Invalid("policy_conflict"));
    }
    let requires_account_approval = input.mode == "self_service" && input.approval_required;
    if inherit && input.app_id.is_some() {
        execute(
            &txn,
            "DELETE FROM registration_policies WHERE app_id=$1",
            vec![input.app_id.into()],
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
        execute(
            &txn,
            "INSERT INTO registration_policies (app_id, mode, domains, approval_required, emergency_stop)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (app_id) DO UPDATE SET mode=EXCLUDED.mode, domains=EXCLUDED.domains,
                 approval_required=EXCLUDED.approval_required, emergency_stop=EXCLUDED.emergency_stop,
                 version=EXCLUDED.version",
            vec![
                input.app_id.into(), input.mode.into(), input.domains.into(),
                input.approval_required.into(), (input.app_id.is_none() && input.emergency_stop).into(),
            ],
        )
        .await?;
    }
    if input.app_id.is_none() {
        let (from, to) = if requires_account_approval {
            ("ready", "pending_approval")
        } else {
            ("pending_approval", "ready")
        };
        execute(
            &txn,
            "UPDATE enrollments SET status=$2 WHERE status=$1 AND NOT invitation
             AND approved_by IS NULL AND verified_at IS NOT NULL AND expires_at>now()",
            vec![from.into(), to.into()],
        )
        .await?;
    }
    super::application_request::close_if_managed(&txn, input.app_id).await?;
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
    pub(crate) fn is_account_invitation(&self) -> bool {
        self.manual_delivery && self.email.is_none()
    }

    pub(crate) fn allows_browser_resend(&self, verified: bool) -> bool {
        !self.invitation
            && (self.status == "pending_verification"
                || (verified && matches!(self.status.as_str(), "pending_approval" | "ready")))
    }

    pub(crate) fn completed_result(&self, session: &SsoSession) -> Option<EnrollmentResult> {
        (self.status == "completed" && self.completed_user_id == Some(session.user_id))
            .then(|| self.result(session.user_id, None, self.tenant_id))
    }

    fn result(
        &self,
        user_id: Uuid,
        identity: Option<identities::Model>,
        tenant_id: Option<Uuid>,
    ) -> EnrollmentResult {
        EnrollmentResult {
            user_id,
            identity,
            app_id: self.app_id,
            client_id: self.client_id,
            auth_request_id: self.auth_request_id,
            tenant_id,
        }
    }
}

pub(crate) async fn check<C: ConnectionTrait>(db: &C, row: &Enrollment) -> Result<Policy, Error> {
    let mut p = policy(db, row.app_id).await?;
    if p.app_id.is_some() && !row.invitation {
        let platform = policy(db, None).await?;
        p.approval_required = platform.mode == "self_service" && platform.approval_required;
    }
    require_personal_app(db, row.app_id).await?;
    if let Some(id) = row.provider_id {
        allow_social(db, id).await?;
    }
    if !row.invitation && row.app_id.is_some() && row.client_id.is_none() {
        return Err(Error::Invalid("enrollment_client_unavailable"));
    }
    if row.phone.is_some() {
        eligible_phone(&p)?;
    } else {
        eligible(
            &p,
            row.email.as_deref(),
            row.invitation,
            row.domain_exception,
        )?;
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
        if !can_invite(&access, row.app_id, row.domain_exception)
            || (row.is_account_invitation() && !access.super_admin)
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

fn can_invite(access: &super::permissions::Access, app: Option<Uuid>, exception: bool) -> bool {
    access.super_admin
        || (app.is_none()
            && !exception
            && access.can_global(super::permissions::Permission::UsersCreate))
}

fn registration_link(state: &AppState, token: &str) -> String {
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(&state.config.sso.base_url, "sso/register");
    pero_utils::encode::append_query_param(&mut link, "token", token);
    link
}

fn require_notification_channel(state: &AppState, channel: &str) -> Result<(), Error> {
    if !state.config.notification.available(channel) {
        return Err(Error::Invalid("notification_disabled"));
    }
    Ok(())
}

async fn enqueue_delivery<C: ConnectionTrait>(
    db: &C,
    state: &AppState,
    id: Uuid,
    contact: (&str, &str),
    token: &str,
    expires: OffsetDateTime,
) -> Result<(), Error> {
    let (channel, address) = contact;
    super::notify::enqueue_enrollment(
        db,
        id,
        &super::notify::Notification {
            channel,
            kind: "enrollment",
            to: address,
            code: None,
            link: &registration_link(state, token),
        },
        expires,
    )
    .await?;
    Ok(())
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationDelivery {
    #[default]
    Email,
    Manual,
    AccountLink,
}

pub async fn invite(
    state: &AppState,
    address: &str,
    app: Option<Uuid>,
    actor: &permissions::Actor,
    exception: bool,
    reason: &str,
    delivery: InvitationDelivery,
) -> Result<Option<String>, Error> {
    let address = match (delivery, address.trim()) {
        (InvitationDelivery::AccountLink, "") => None,
        (InvitationDelivery::AccountLink, _) => {
            return Err(Error::Invalid("invalid_request"));
        }
        (_, address) => Some(email(address)?),
    };
    start_contact(
        state,
        address.as_deref(),
        app,
        false,
        StartKind::Invitation {
            actor,
            exception,
            reason,
            delivery,
        },
    )
    .await
    .map(|started| started.activation_link)
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
        Some(&address),
        request.map(|request| request.app_id),
        is_phone,
        StartKind::SelfService {
            request,
            social: None,
            previous,
        },
    )
    .await
    .map(|started| started.id)
}

enum StartKind<'a> {
    Invitation {
        actor: &'a permissions::Actor,
        exception: bool,
        reason: &'a str,
        delivery: InvitationDelivery,
    },
    SelfService {
        request: Option<&'a Authorization>,
        social: Option<(Uuid, &'a str)>,
        previous: Option<Uuid>,
    },
}

struct StartedEnrollment {
    id: Uuid,
    activation_link: Option<String>,
}

async fn start_contact(
    state: &AppState,
    address: Option<&str>,
    app: Option<Uuid>,
    is_phone: bool,
    kind: StartKind<'_>,
) -> Result<StartedEnrollment, Error> {
    let manual = matches!(
        &kind,
        StartKind::Invitation {
            delivery: InvitationDelivery::Manual | InvitationDelivery::AccountLink,
            ..
        }
    );
    let account_invitation = manual && address.is_none();
    let txn = state.db.begin().await?;
    let (invitation, source, social, previous) = match kind {
        StartKind::Invitation {
            actor,
            exception,
            reason,
            ..
        } => (Some((actor, exception, reason)), None, None, None),
        StartKind::SelfService {
            request,
            social,
            previous,
        } => {
            super::admin::read_lock_policy(&txn).await?;
            (None, request.map(ApplicationSource::from), social, previous)
        }
    };
    let (client_id, request_id) = if let Some(source) = source {
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
        let request = active.ok_or(Error::Invalid("enrollment_request_expired"))?;
        if request.tenant_id.is_some() {
            return Err(Error::Invalid("enrollment_organization_required"));
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
        (Some(source.client_id), Some(request.id))
    } else {
        (None, None)
    };
    let (invited, actor, exception, reason) = if let Some((actor, exception, reason)) = invitation {
        let access = permissions::authorize(&txn, actor).await?;
        if !can_invite(&access, app, exception)
            || (!access.super_admin && (manual || !reason.is_empty()))
        {
            return Err(Error::Invalid("forbidden"));
        }
        if reason.len() > 500 || (exception && reason.trim().is_empty()) {
            return Err(Error::Invalid("invalid_request"));
        }
        (true, Some(actor.session.user_id), exception, reason)
    } else {
        (false, None, false, "")
    };
    require_personal_app(&txn, app).await?;
    if let Some((provider, _)) = social {
        allow_social(&txn, provider).await?;
    }
    let p = policy(&txn, app).await?;
    if is_phone {
        eligible_phone(&p)?;
    } else {
        eligible(&p, address, invited, exception)?;
    }
    let provider_id = social.map(|s| s.0);
    let subject = social.map(|s| s.1);
    if let Some(previous) = previous {
        let existing = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM enrollments WHERE NOT invitation AND id=$1
             AND app_id IS NOT DISTINCT FROM $2::uuid AND client_id IS NOT DISTINCT FROM $3::uuid
             AND auth_request_id IS NOT DISTINCT FROM $4::uuid
             AND provider_id IS NOT DISTINCT FROM $5::uuid AND subject IS NOT DISTINCT FROM $6::text
             AND (email=$7::citext OR phone=$8::citext) AND expires_at>now()
             AND status IN ('pending_verification','pending_approval','ready')",
                [
                    previous.into(),
                    app.into(),
                    client_id.into(),
                    request_id.into(),
                    provider_id.into(),
                    subject.into(),
                    address.filter(|_| !is_phone).into(),
                    address.filter(|_| is_phone).into(),
                ],
            ))
            .await?;
        if let Some(row) = existing {
            return Ok(StartedEnrollment {
                id: row.try_get("", "id")?,
                activation_link: None,
            });
        }
    }
    // Only addressed invitations compete for the partial unique index.
    if invited && let Some(address) = address {
        if app.is_some()
            && users::Entity::find()
                .filter(users::Column::Email.eq(address))
                .filter(users::Column::DeletedAt.is_null())
                .one(&txn)
                .await?
                .is_some()
        {
            return Err(Error::Invalid("enrollment_existing_app_invitee"));
        }
        let pending = txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM enrollments WHERE invitation AND email=$1::citext AND (app_id=$2 OR ($2::uuid IS NULL AND app_id IS NULL))
             AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",
            [address.into(), app.into()],
        )).await?;
        if pending.is_some() {
            return Err(Error::Invalid("enrollment_invitation_exists"));
        }
        execute(
            &txn,
            "UPDATE enrollments SET status='expired' WHERE invitation AND email=$1::citext AND (app_id=$2 OR ($2::uuid IS NULL AND app_id IS NULL)) AND expires_at<=now() AND status IN ('pending_verification','pending_approval','ready')",
            vec![address.into(), app.into()],
        )
        .await?;
    }
    let delivery_contact = if manual {
        None
    } else {
        let channel = if is_phone { "phone" } else { "email" };
        let address = address.ok_or_else(invalid)?;
        require_notification_channel(state, channel)?;
        limit_contact(state, address, invited).await?;
        Some((channel, address))
    };
    let token = pero_utils::crypto::generate_token();
    let id = Uuid::now_v7();
    let expiry = OffsetDateTime::now_utc() + time::Duration::hours(if invited { 72 } else { 24 });
    execute(
        &txn,
        "INSERT INTO enrollments (
            id,app_id,email,phone,invitation,invited_by,domain_exception,reason,token_hash,expires_at,
            client_id,auth_request_id,provider_id,subject,manual_delivery,status
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        vec![
            id.into(),
            app.into(),
            address.filter(|_| !is_phone).into(),
            address.filter(|_| is_phone).into(),
            invited.into(),
            actor.into(),
            exception.into(),
            reason.into(),
            pero_utils::crypto::sha256_hex(&token).into(),
            expiry.into(),
            client_id.into(),
            request_id.into(),
            provider_id.into(),
            subject.into(),
            manual.into(),
            (if account_invitation { "ready" } else { "pending_verification" }).into(),
        ],
    )
    .await?;
    if let Some(contact) = delivery_contact {
        enqueue_delivery(&txn, state, id, contact, &token, expiry).await?;
    }
    txn.commit().await?;
    Ok(StartedEnrollment {
        id,
        activation_link: manual.then(|| registration_link(state, &token)),
    })
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
    actor: &permissions::Actor,
    id: Uuid,
    action: &str,
    reason: &str,
) -> Result<Option<String>, Error> {
    let txn = state.db.begin().await?;
    permissions::require_super(&txn, actor).await?;
    let actor_id = actor.session.user_id;
    let row=Enrollment::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT * FROM enrollments WHERE id=$1 AND expires_at>now() AND status IN ('pending_verification','pending_approval','ready')",[id.into()])).one(&txn).await?.ok_or_else(invalid)?;
    if reason.len() > 500 {
        return Err(Error::Invalid("invalid_request"));
    }
    let mut activation_link = None;
    match action {
        "approve" | "reject" if row.status == "pending_approval" => {
            let own = users::Entity::find_by_id(actor_id)
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
            execute(&txn,"UPDATE enrollments SET status=$2,approved_by=$3,approved_at=now(),reason=$4,token_hash=$5,last_sent_at=now() WHERE id=$1",vec![id.into(),(if action=="approve" {"ready"} else {"rejected"}).into(),actor_id.into(),reason.into(),pero_utils::crypto::sha256_hex(&token).into()]).await?;
            cancel_notifications(&txn, id).await?;
            if action == "approve" {
                let contact = contact(&row)?;
                require_notification_channel(state, contact.0)?;
                enqueue_delivery(&txn, state, id, contact, &token, row.expires_at).await?;
            } else {
                let (channel, to) = contact(&row)?;
                super::notify::enqueue_enrollment(
                    &txn,
                    id,
                    &super::notify::Notification {
                        channel,
                        kind: "enrollment_rejected",
                        to,
                        code: None,
                        link: &registration_link(state, &token),
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
        "issue_link" if row.invitation => {
            check_redelivery(&txn, &row).await?;
            let token = rotate_token(&txn, &row, true).await?;
            activation_link = Some(registration_link(state, &token));
        }
        _ => return Err(invalid()),
    }
    txn.commit().await?;
    Ok(activation_link)
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

async fn rotate_token<C: ConnectionTrait>(
    db: &C,
    row: &Enrollment,
    manual_delivery: bool,
) -> Result<String, Error> {
    let token = pero_utils::crypto::generate_token();
    execute(
        db,
        "UPDATE enrollments SET token_hash=$2,last_sent_at=now(),manual_delivery=$3 WHERE id=$1",
        vec![
            row.id.into(),
            pero_utils::crypto::sha256_hex(&token).into(),
            manual_delivery.into(),
        ],
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
    check_redelivery(db, row).await?;
    let contact = contact(row)?;
    require_notification_channel(state, contact.0)?;
    if limit_recipient {
        limit_contact(state, contact.1, false).await?;
    }
    let token = rotate_token(db, row, false).await?;
    enqueue_delivery(db, state, row.id, contact, &token, row.expires_at).await
}

async fn check_redelivery<C: ConnectionTrait>(db: &C, row: &Enrollment) -> Result<(), Error> {
    if row.last_sent_at > OffsetDateTime::now_utc() - time::Duration::seconds(60) {
        return Err(Error::Invalid("rate_limited"));
    }
    check(db, row).await?;
    Ok(())
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
    } else if let Some(phone) = &row.phone {
        users::Column::Phone.eq(phone.clone())
    } else {
        return Ok(None);
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
        .is_some_and(|access| {
            access.status == CommonStatus::Active && access.admission_origin == "explicit"
        }))
}

pub struct EnrollmentResult {
    pub user_id: Uuid,
    pub identity: Option<identities::Model>,
    pub app_id: Option<Uuid>,
    pub client_id: Option<Uuid>,
    pub auth_request_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
}

#[derive(Default)]
pub struct FinalizeInput<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub email: &'a str,
    pub phone: &'a str,
}

pub async fn finalize(
    state: &AppState,
    token: &str,
    input: FinalizeInput<'_>,
    session: Option<&SsoSession>,
    social_proof: Option<&SocialProof>,
) -> Result<EnrollmentResult, Error> {
    let initial = lookup(&state.db, token).await?;
    if initial.verified_at.is_none() && !initial.is_account_invitation() {
        return Err(Error::Invalid("approval_required"));
    }
    let existing = existing_account(&state.db, &initial).await?;
    let exists = existing.is_some();
    if !exists && session.is_some() {
        return Err(Error::Invalid("enrollment_sign_out_required"));
    }
    if !exists && initial.status != "ready" {
        return Err(Error::Invalid("approval_required"));
    }
    let (account_email, account_phone) = if initial.is_account_invitation() {
        let email = (!input.email.trim().is_empty())
            .then(|| email(input.email))
            .transpose()?;
        let phone = (!input.phone.trim().is_empty())
            .then(|| phone(input.phone))
            .transpose()?;
        (email, phone)
    } else {
        (None, None)
    };
    if !exists {
        crate::db::helper::user::validate_username(input.username).map_err(Error::Invalid)?;
    }
    let hash = if !exists && initial.provider_id.is_none() {
        state
            .config
            .password
            .validate_password(input.password)
            .map_err(Error::Validation)?;
        Some(PasswordIdentityService::hash_password(input.password).await?)
    } else {
        None
    };
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let row = lookup(&txn, token).await?;
    let p = check(&txn, &row).await?;
    let existing = existing_account(&txn, &row).await?;
    if row.invitation && row.app_id.is_some() && existing.is_some() {
        return Err(Error::Invalid("enrollment_existing_app_invitee"));
    }
    if row.verified_at.is_none() && !row.is_account_invitation() {
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
    // A matching account has already cleared account creation. OAuth checks
    // application access separately when this enrollment resumes.
    if existing_session.is_none()
        && (row.status != "ready"
            || (!row.invitation && p.approval_required && row.approved_by.is_none()))
    {
        return Err(Error::Invalid("approval_required"));
    }
    let mut identity = None;
    let user = if let Some(session) = existing_session {
        let user =
            super::account_security::lock_account_session(&txn, session, &state.config.sso).await?;
        let contact_matches = if let Some(email_address) = &row.email {
            user.email.as_deref().and_then(|v| email(v).ok()).as_deref()
                == Some(email_address.as_str())
        } else {
            user.phone.as_deref() == row.phone.as_deref()
        };
        if !contact_matches || super::security::role(&txn, user.id).await?.is_some() {
            return Err(invalid());
        }
        if !row.manual_delivery
            && (row.email.is_some() && user.email_verified_at.is_none()
                || row.phone.is_some() && user.phone_verified_at.is_none())
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
        let (user, created_identity) = super::user::create_registered_user(
            &txn,
            input.username,
            row.email.clone(),
            row.phone.clone(),
            !row.manual_delivery,
            credential,
        )
        .await?;
        use super::contact::{ContactChannel, ContactError, ContactVerificationService};
        for (channel, value) in [
            (ContactChannel::Email, account_email),
            (ContactChannel::Phone, account_phone),
        ] {
            let Some(value) = value else { continue };
            if !state.config.notification.available(channel.key()) {
                return Err(Error::Invalid("notification_disabled"));
            }
            ContactVerificationService::create_request_in_transaction(
                &txn,
                user.id,
                channel,
                value,
                Some(&state.config.sso.base_url),
            )
            .await
            .map_err(|error| match error {
                ContactError::ContactTaken => Error::Invalid("contact_taken"),
                _ => Error::Dependency(sea_orm::DbErr::Custom(
                    "Could not prepare contact verification".into(),
                )),
            })?;
        }
        identity = Some(created_identity);
        user
    };
    if let (Some(app), Some(inviter)) = (row.app_id, row.invited_by) {
        super::access::ordinary_app(&txn, app).await?;
        super::access::grant_explicit(&txn, user.id, app, inviter, "app_access_invited", false)
            .await?;
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
    Ok(row.result(user.id, identity, tenant_id))
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
        Some(&address),
        request.map(|request| request.app_id),
        false,
        StartKind::SelfService {
            request,
            social: Some((provider, subject)),
            previous,
        },
    )
    .await
    .map(|started| started.id)
}

pub(crate) async fn supports_personal_enrollment<C: ConnectionTrait>(
    db: &C,
    app: Option<Uuid>,
) -> Result<bool, sea_orm::DbErr> {
    match app {
        None => Ok(true),
        Some(app) => Ok(apps::Entity::find_by_id(app)
            .one(db)
            .await?
            .is_some_and(|app| app.tenant_mode != "organization")),
    }
}

async fn require_personal_app<C: ConnectionTrait>(db: &C, app: Option<Uuid>) -> Result<(), Error> {
    if !supports_personal_enrollment(db, app).await? {
        return Err(Error::Invalid("enrollment_unavailable"));
    }
    Ok(())
}

async fn limit_contact(state: &AppState, address: &str, invitation: bool) -> Result<(), Error> {
    use pero_cache_redis::rate_limit_key::{rl_enrollment_email, rl_enrollment_invite_recipient};

    let hash = pero_utils::crypto::hmac_sha256(
        address.as_bytes(),
        state
            .config
            .sso
            .cookie_signing_secret
            .expose_secret()
            .as_bytes(),
    );
    let key = if invitation {
        rl_enrollment_invite_recipient.key(&hash)?
    } else {
        rl_enrollment_email.key(&hash)?
    };
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
    execute(
        db,
        "WITH revoked AS (
            UPDATE enrollments SET status='revoked'
            WHERE (invited_by=$1 OR approved_by=$1)
              AND status IN ('pending_verification','pending_approval','ready')
            RETURNING id
         )
         DELETE FROM notification_outbox o USING revoked WHERE o.enrollment_id=revoked.id",
        vec![user.into()],
    )
    .await
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
            app_id: None,
            mode: "self_service".into(),
            domains: vec!["example.com".into()],
            approval_required: true,
            emergency_stop: false,
            version: 1,
        };
        assert!(eligible(&p, Some("a@example.com"), false, false).is_ok());
        assert!(eligible(&p, Some("a@sub.example.com"), false, false).is_err());
        p.mode = "invite_only".into();
        assert!(eligible(&p, Some("a@example.com"), false, false).is_err());
        assert!(eligible(&p, Some("a@external.com"), true, true).is_ok());
        assert!(eligible(&p, None, true, false).is_err());
        assert!(eligible(&p, None, true, true).is_ok());
        p.emergency_stop = true;
        assert!(eligible(&p, Some("a@example.com"), true, false).is_err());
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
      AND ($3::uuid IS NULL OR completed_user_id=$3
           OR (completed_user_id IS NULL AND (NOT invitation OR app_id IS NULL)
               AND (email=$4::citext OR phone=$5::citext)))
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
    let rows = ProgressRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        format!(
            "SELECT id,app_id,app_name,COALESCE(email::text,phone::text,'') AS email,
                    invitation,effective_status AS status,
                    CASE WHEN $3::uuid IS NOT NULL AND (domain_exception OR (manual_delivery AND email IS NULL))
                         THEN '' ELSE reason END AS reason,
                    created_at,expires_at
             {filter} AND ($7='' OR effective_status=$7)
             ORDER BY (effective_status='pending_approval') DESC,created_at DESC,id DESC LIMIT $8 OFFSET $9"
        ),
        values,
    ))
    .all(db)
    .await?;
    Ok(ProgressList {
        rows,
        page,
        total_pages: (counts.total as u64).div_ceil(crate::config::DASHBOARD_PAGE_SIZE),
        pending_count: counts.pending,
    })
}

/// Only flows available to existing accounts can be managed through the portal.
pub async fn owner_action(
    state: &AppState,
    actor: &SsoSession,
    id: Uuid,
    action: &str,
) -> Result<Option<String>, Error> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let user =
        super::account_security::lock_account_session(&txn, actor, &state.config.sso).await?;
    let row = Enrollment::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT * FROM enrollments WHERE id=$1 AND (NOT invitation OR app_id IS NULL)
         AND (email=$2::citext OR phone=$3::citext) AND expires_at>now()
         AND status IN ('pending_verification','pending_approval','ready')",
        [
            id.into(),
            user.email
                .as_deref()
                .filter(|_| user.email_verified_at.is_some())
                .into(),
            user.phone
                .as_deref()
                .filter(|_| user.phone_verified_at.is_some())
                .into(),
        ],
    ))
    .one(&txn)
    .await?
    .ok_or_else(invalid)?;
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
        "resend" => {
            redeliver(&txn, state, &row, false).await?;
            None
        }
        "continue" => {
            check(&txn, &row).await?;
            Some(rotate_token(&txn, &row, row.manual_delivery).await?)
        }
        _ => return Err(Error::Invalid("invalid_request")),
    };
    audit(&txn, &user, &format!("enrollment_{action}"), id).await?;
    txn.commit().await?;
    Ok(token)
}
