use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::entity::authorization_requests;
use crate::db::enums::CodeChallengeMethod;

pub struct CreateParams {
    pub client_id: Uuid,
    pub app_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub client_state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
    pub expires_at: OffsetDateTime,
}

pub async fn create(
    db: &DatabaseConnection,
    params: CreateParams,
) -> Result<authorization_requests::Model, sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    let model = authorization_requests::ActiveModel {
        id: Set(Uuid::now_v7()),
        client_id: Set(params.client_id),
        app_id: Set(params.app_id),
        redirect_uri: Set(params.redirect_uri),
        scopes: Set(params.scopes),
        client_state: Set(params.client_state),
        nonce: Set(params.nonce),
        code_challenge: Set(params.code_challenge),
        code_challenge_method: Set(params.code_challenge_method),
        prompt: Set(params.prompt),
        max_age: Set(params.max_age),
        login_hint: Set(params.login_hint),
        authorized_user_id: Set(None),
        created_at: Set(now),
        expires_at: Set(params.expires_at),
        completed_at: Set(None),
    };
    model.insert(db).await
}
