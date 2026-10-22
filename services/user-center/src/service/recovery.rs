//! Recovery credentials and their pending notifications share the user's lock.
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, DbErr, EntityTrait, QueryFilter, Statement,
    sea_query::Expr,
};
use uuid::Uuid;

/// Call inside a transaction after locking the user. This also covers tokens
/// issued before notification ownership metadata was introduced.
pub async fn invalidate<C: ConnectionTrait>(db: &C, user_id: Uuid) -> Result<(), DbErr> {
    use crate::db::entity::password_reset_tokens as prt;
    prt::Entity::update_many()
        .col_expr(
            prt::Column::ConsumedAt,
            Expr::value(Some(time::OffsetDateTime::now_utc())),
        )
        .filter(prt::Column::UserId.eq(user_id))
        .filter(prt::Column::ConsumedAt.is_null())
        .exec(db)
        .await?;
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM notification_outbox WHERE user_id = $1 AND kind = 'reset_password'",
        [user_id.into()],
    ))
    .await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("Recovery dependency unavailable")]
    Dependency(#[from] DbErr),
    #[error("Could not sign recovery token")]
    Signing(#[from] jsonwebtoken::errors::Error),
    #[error("Notifications are not configured")]
    NotConfigured,
}

/// Nonexistent/inactive accounts remain indistinguishable from accepted requests.
/// Dependency failures are not evidence that the account does not exist.
pub async fn request(
    state: &crate::state::app::AppState,
    identifier: &str,
) -> Result<(), RecoveryError> {
    use crate::db::{
        entity::{identities, password_reset_tokens, users},
        enums::{IdentityKind, UserStatus},
    };
    use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
    if state.config.notification.endpoint.is_empty() {
        return Err(RecoveryError::NotConfigured);
    }
    let user = users::Entity::find()
        .filter(
            sea_orm::Condition::any()
                .add(users::Column::Email.eq(identifier))
                .add(users::Column::Phone.eq(identifier)),
        )
        .filter(users::Column::DeletedAt.is_null())
        .filter(users::Column::Status.eq(UserStatus::Active))
        .one(&state.db)
        .await?;
    let Some(user) = user else {
        return Ok(());
    };
    let txn = state.db.begin().await?;
    let user = match super::password::PasswordIdentityService::lock_user(&txn, user.id).await {
        Ok(user) if user.status == UserStatus::Active => user,
        Ok(_) | Err(DbErr::RecordNotFound(_)) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // Recovery changes an existing local password. Social-only users set their
    // first password from an authenticated account session instead.
    if identities::Entity::find()
        .filter(identities::Column::UserId.eq(user.id))
        .filter(identities::Column::Kind.eq(IdentityKind::Password))
        .filter(identities::Column::UnboundAt.is_null())
        .one(&txn)
        .await?
        .is_none_or(|identity| identity.password_hash.is_none_or(|hash| hash.is_empty()))
    {
        return Ok(());
    }
    // Contact changes and issuance use the same user lock.
    let (channel, recipient) = if let Some(email) = user
        .email
        .as_deref()
        .filter(|email| email.eq_ignore_ascii_case(identifier))
    {
        ("email", email)
    } else if let Some(phone) = user.phone.as_deref()
        && (phone == identifier
            || phone == pero_utils::string::canonical_rate_limit_key(identifier))
    {
        ("phone", phone)
    } else {
        return Ok(());
    };
    let token = pero_utils::oauth::jwt::sign_password_reset_token(
        &user.id.to_string(),
        state.config.password_reset.ttl_seconds as i64,
        state.config.password_reset.signing_key.expose_secret(),
    )?;
    let now = time::OffsetDateTime::now_utc();
    let expires_at =
        super::verification::expires_in_seconds(state.config.password_reset.ttl_seconds);
    password_reset_tokens::ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(user.id),
        token_hash: Set(pero_utils::crypto::sha256_hex(&token)),
        issued_at: Set(now),
        expires_at: Set(expires_at),
        consumed_at: Set(None),
    }
    .insert(&txn)
    .await?;
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(&state.config.sso.base_url, "sso/reset-password");
    pero_utils::encode::append_query_param(&mut link, "token", &token);
    super::notify::enqueue(
        &txn,
        user.id,
        &super::notify::Notification {
            channel,
            kind: "reset_password",
            to: recipient,
            code: None,
            link: &link,
        },
        expires_at,
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
