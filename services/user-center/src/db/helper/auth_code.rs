use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::entity::authorization_codes;
use crate::db::enums::CodeChallengeMethod;

pub struct CreateParams {
    pub code_hash: String,
    pub authorization_request_id: Option<Uuid>,
    pub user_id: Uuid,
    pub app_id: Uuid,
    pub client_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub expires_at: OffsetDateTime,
}

pub async fn create<C>(
    db: &C,
    params: CreateParams,
) -> Result<authorization_codes::Model, sea_orm::DbErr>
where
    C: ConnectionTrait,
{
    let now = OffsetDateTime::now_utc();
    let model = authorization_codes::ActiveModel {
        id: Set(Uuid::now_v7()),
        code_hash: Set(params.code_hash),
        authorization_request_id: Set(params.authorization_request_id),
        user_id: Set(params.user_id),
        app_id: Set(params.app_id),
        client_id: Set(params.client_id),
        session_id: Set(Some(params.session_id)),
        redirect_uri: Set(params.redirect_uri),
        scopes: Set(params.scopes),
        nonce: Set(params.nonce),
        code_challenge: Set(params.code_challenge),
        code_challenge_method: Set(params.code_challenge_method),
        created_at: Set(now),
        expires_at: Set(params.expires_at),
        consumed_at: Set(None),
    };
    model.insert(db).await
}

pub async fn consume_if_valid<C>(
    db: &C,
    id: Uuid,
    client_id: Uuid,
    redirect_uri: &str,
    now: OffsetDateTime,
) -> Result<bool, sea_orm::DbErr>
where
    C: ConnectionTrait,
{
    let result = authorization_codes::Entity::update_many()
        .col_expr(
            authorization_codes::Column::ConsumedAt,
            sea_orm::sea_query::Expr::value(Some(now)),
        )
        .filter(authorization_codes::Column::Id.eq(id))
        .filter(authorization_codes::Column::ClientId.eq(client_id))
        .filter(authorization_codes::Column::RedirectUri.eq(redirect_uri))
        .filter(authorization_codes::Column::ExpiresAt.gt(now))
        .filter(authorization_codes::Column::ConsumedAt.is_null())
        .exec(db)
        .await?;

    Ok(result.rows_affected == 1)
}
