//! Fixed security policy; credentials never leave enrollment/recovery responses.
use super::ManagementError;
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement};
use time::OffsetDateTime;
use uuid::Uuid;
pub const RECENT_SECONDS: i64 = 900;

pub async fn execute<C: ConnectionTrait>(
    db: &C,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await?;
    Ok(())
}
#[derive(FromQueryResult)]
struct Role {
    role: String,
}
pub async fn role<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<Option<String>, DbErr> {
    Ok(Role::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT role FROM admin_roles WHERE user_id=$1",
        [user.into()],
    ))
    .one(db)
    .await?
    .map(|r| r.role))
}
pub async fn mfa_enabled<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<bool, DbErr> {
    #[derive(FromQueryResult)]
    struct Enabled {
        enabled: bool,
    }
    Ok(Enabled::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT enabled FROM user_mfa WHERE user_id=$1",
        [user.into()],
    ))
    .one(db)
    .await?
    .is_some_and(|r| r.enabled))
}
#[derive(FromQueryResult)]
pub struct Factor {
    pub secret: String,
    pub pending_secret: Option<String>,
    pub setup_session: Option<Uuid>,
    pub enabled: bool,
    pub setup_expires_at: OffsetDateTime,
    pub last_step: i64,
    pub recovery_hashes: Vec<String>,
    pub assisted_recovery_hash: Option<String>,
    pub assisted_recovery_expires_at: Option<OffsetDateTime>,
}
pub async fn factor<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<Option<Factor>, DbErr> {
    Factor::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT pgp_sym_decrypt(secret_enc,current_setting('app.encrypt_key')) AS secret, pgp_sym_decrypt(pending_secret_enc,current_setting('app.encrypt_key')) AS pending_secret, setup_session,enabled, setup_expires_at,last_step,recovery_hashes,assisted_recovery_hash,assisted_recovery_expires_at FROM user_mfa WHERE user_id=$1", [user.into()])).one(db).await
}
pub fn totp(secret: &str, account: &str) -> Result<totp_rs::Totp, ManagementError> {
    let secret = totp_rs::Secret::try_from_base32(secret)
        .map_err(|_| ManagementError::Invalid("invalid_request"))?;
    totp_rs::Builder::new()
        .with_secret(secret)
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_issuer(Some("Pero"))
        .with_account_name(account)
        .build()
        .map_err(|_| ManagementError::Invalid("invalid_request"))
}
/// Caller loads the factor under the user's credential lock and keeps it until
/// commit. Successful steps and recovery codes cannot be replayed.
pub(super) async fn verify<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    factor: Option<&Factor>,
    code: &str,
    recovery: bool,
) -> Result<(), ManagementError> {
    let f = factor.ok_or(ManagementError::Invalid("mfa_not_enabled"))?;
    if !f.enabled {
        return Err(ManagementError::Invalid("mfa_not_enabled"));
    }
    if recovery {
        let hash = pero_utils::crypto::sha256_hex(code.trim());
        let assisted = f.assisted_recovery_hash.as_deref() == Some(hash.as_str())
            && f.assisted_recovery_expires_at
                .is_some_and(|at| at > OffsetDateTime::now_utc());
        if !f.recovery_hashes.contains(&hash) && !assisted {
            return Err(ManagementError::Invalid("invalid_mfa_code"));
        }
        execute(
            db,
            "UPDATE user_mfa SET recovery_hashes=array_remove(recovery_hashes,$2),assisted_recovery_hash=NULL,assisted_recovery_expires_at=NULL WHERE user_id=$1",
            vec![user.into(), hash.into()],
        )
        .await?;
        return Ok(());
    }
    let step = verified_step(f, code)?;
    execute(
        db,
        "UPDATE user_mfa SET last_step=$2 WHERE user_id=$1",
        vec![user.into(), step.into()],
    )
    .await?;
    Ok(())
}
pub fn verified_step(f: &Factor, code: &str) -> Result<i64, ManagementError> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ManagementError::Invalid("invalid_mfa_code"));
    }
    let current = OffsetDateTime::now_utc().unix_timestamp() / 30;
    let otp = totp(&f.secret, "account")?;
    for step in [current, current - 1, current + 1] {
        if step > f.last_step
            && pero_utils::crypto::constant_time_eq(
                otp.generate((step * 30) as u64).to_string().as_bytes(),
                code.as_bytes(),
            )
        {
            return Ok(step);
        }
    }
    Err(ManagementError::Invalid("invalid_mfa_code"))
}
pub async fn recent<C: ConnectionTrait>(
    db: &C,
    session: Uuid,
    idle_ttl_seconds: u64,
) -> Result<bool, DbErr> {
    use crate::db::{entity::sso_sessions, helper::session::valid_query};
    use sea_orm::{ColumnTrait, QueryFilter};
    let now = OffsetDateTime::now_utc();
    let s = valid_query(now, idle_ttl_seconds)
        .filter(sso_sessions::Column::Id.eq(session))
        .one(db)
        .await?;
    Ok(s.is_some_and(|s| {
        !s.recovery_pending
            && s.reauthenticated_at
                .is_some_and(|at| at > now - time::Duration::seconds(RECENT_SECONDS))
            && (!s.mfa_required
                || s.mfa_verified_at
                    .is_some_and(|at| at > now - time::Duration::seconds(RECENT_SECONDS)))
    }))
}
pub async fn codes<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<Vec<String>, DbErr> {
    let codes: Vec<_> = (0..8)
        .map(|_| pero_utils::crypto::generate_nonce())
        .collect();
    let hashes: Vec<_> = codes
        .iter()
        .map(|s| pero_utils::crypto::sha256_hex(s))
        .collect();
    execute(
        db,
        "UPDATE user_mfa SET recovery_hashes=$2,assisted_recovery_hash=NULL,assisted_recovery_expires_at=NULL WHERE user_id=$1",
        vec![user.into(), hashes.into()],
    )
    .await?;
    Ok(codes)
}
pub async fn notify<C: ConnectionTrait>(
    db: &C,
    user: &crate::db::entity::users::Model,
    kind: &str,
) -> Result<(), DbErr> {
    for (channel, to, verified) in [
        (
            "email",
            user.email.as_deref(),
            user.email_verified_at.is_some(),
        ),
        (
            "phone",
            user.phone.as_deref(),
            user.phone_verified_at.is_some(),
        ),
    ] {
        if let Some(to) = to.filter(|_| verified) {
            super::notify::enqueue(
                db,
                user.id,
                &super::notify::Notification {
                    channel,
                    kind,
                    to,
                    code: None,
                    link: "",
                },
                OffsetDateTime::now_utc() + time::Duration::days(1),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc6238_sha1_six_digit_vector() {
        let totp = super::totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "rfc-test").unwrap();
        assert_eq!(totp.generate(59).to_string(), "287082");
    }
}
