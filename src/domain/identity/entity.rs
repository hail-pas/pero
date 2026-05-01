use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub status: i16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn is_active(&self) -> bool {
        self.status == 1
    }
}

#[derive(Debug, sqlx::FromRow, Serialize, Clone, ToSchema)]
pub struct Identity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_uid: String,
    #[serde(skip_serializing)]
    pub credential: Option<String>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
