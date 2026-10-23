use ipnetwork::IpNetwork;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, sea_query::Expr,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::entity::sso_sessions;

pub struct CreateParams {
    pub token_hash: String,
    pub user_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub provider_id: Option<Uuid>,
    pub ip: Option<IpNetwork>,
    pub user_agent: Option<String>,
    pub expires_at: OffsetDateTime,
    pub authenticated_at: OffsetDateTime,
}

pub async fn create<C>(db: &C, params: CreateParams) -> Result<sso_sessions::Model, sea_orm::DbErr>
where
    C: ConnectionTrait,
{
    let now = OffsetDateTime::now_utc();
    let model = sso_sessions::ActiveModel {
        id: Set(Uuid::now_v7()),
        token_hash: Set(params.token_hash),
        user_id: Set(params.user_id),
        identity_id: Set(params.identity_id),
        provider_id: Set(params.provider_id),
        ip: Set(params.ip),
        user_agent: Set(params.user_agent),
        created_at: Set(now),
        authenticated_at: Set(params.authenticated_at),
        last_seen_at: Set(now),
        expires_at: Set(params.expires_at),
        revoked_at: Set(None),
        revoke_reason: Set(None),
    };
    model.insert(db).await
}

pub async fn revoke<C>(db: &C, id: Uuid, reason: Option<String>) -> Result<(), sea_orm::DbErr>
where
    C: ConnectionTrait,
{
    let now = OffsetDateTime::now_utc();
    let session = sso_sessions::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(sea_orm::DbErr::RecordNotFound("session not found".into()))?;
    let mut active: sso_sessions::ActiveModel = session.into();
    active.revoked_at = Set(Some(now));
    active.revoke_reason = Set(reason);
    active.update(db).await?;
    Ok(())
}

pub async fn revoke_all_for_user<C>(
    db: &C,
    user_id: Uuid,
    reason: Option<String>,
) -> Result<(), sea_orm::DbErr>
where
    C: ConnectionTrait,
{
    let now = OffsetDateTime::now_utc();

    sso_sessions::Entity::update_many()
        .col_expr(sso_sessions::Column::RevokedAt, Expr::value(Some(now)))
        .col_expr(sso_sessions::Column::RevokeReason, Expr::value(reason))
        .filter(sso_sessions::Column::UserId.eq(user_id))
        .filter(sso_sessions::Column::RevokedAt.is_null())
        .exec(db)
        .await?;

    Ok(())
}

pub async fn touch_last_seen_after<C: ConnectionTrait>(
    db: &C,
    id: Uuid,
    interval_seconds: u64,
) -> Result<(), sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    // Never extend revoked sessions or move activity time backwards.
    sso_sessions::Entity::update_many()
        .col_expr(sso_sessions::Column::LastSeenAt, Expr::value(now))
        .filter(sso_sessions::Column::Id.eq(id))
        .filter(sso_sessions::Column::RevokedAt.is_null())
        .filter(
            sso_sessions::Column::LastSeenAt
                .lt(now - time::Duration::seconds(interval_seconds as i64)),
        )
        .exec(db)
        .await?;
    Ok(())
}
/// A single validity policy for browser sessions, grants and online token use.
pub fn active_query(
    now: OffsetDateTime,
    idle_ttl_seconds: u64,
) -> sea_orm::Select<sso_sessions::Entity> {
    sso_sessions::Entity::find()
        .filter(sso_sessions::Column::RevokedAt.is_null())
        .filter(sso_sessions::Column::ExpiresAt.gt(now))
        .filter(
            sso_sessions::Column::LastSeenAt
                .gt(now - time::Duration::seconds(idle_ttl_seconds as i64)),
        )
}

/// Called after the user policy lock; keep revocation from racing a credential write.
pub async fn lock_active<C: ConnectionTrait>(
    db: &C,
    session_id: Uuid,
    user_id: Uuid,
    idle_ttl_seconds: u64,
) -> Result<Option<sso_sessions::Model>, sea_orm::DbErr> {
    use sea_orm::QuerySelect;
    active_query(OffsetDateTime::now_utc(), idle_ttl_seconds)
        .filter(sso_sessions::Column::Id.eq(session_id))
        .filter(sso_sessions::Column::UserId.eq(user_id))
        .lock_shared()
        .one(db)
        .await
}
