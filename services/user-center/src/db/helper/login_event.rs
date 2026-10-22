use ipnetwork::IpNetwork;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::entity::login_events;
use crate::db::enums::LoginEventType;

pub struct RecordParams {
    pub user_id: Option<Uuid>,
    pub identity_id: Option<Uuid>,
    pub provider_id: Option<Uuid>,
    pub event_type: LoginEventType,
    pub ip: Option<IpNetwork>,
    pub user_agent: Option<String>,
    pub detail: Value,
}

pub async fn record(
    db: &DatabaseConnection,
    params: RecordParams,
) -> Result<login_events::Model, sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    let model = login_events::ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(params.user_id),
        identity_id: Set(params.identity_id),
        provider_id: Set(params.provider_id),
        event_type: Set(params.event_type),
        ip: Set(params.ip),
        user_agent: Set(params.user_agent),
        detail: Set(params.detail),
        created_at: Set(now),
    };
    model.insert(db).await
}
