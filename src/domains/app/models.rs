use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, sqlx::FromRow, Serialize, Clone)]
pub struct App {
    pub id: Uuid,
    pub name: String,
    pub code: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AppDTO {
    pub id: Uuid,
    pub name: String,
    pub code: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<App> for AppDTO {
    fn from(a: App) -> Self {
        Self {
            id: a.id,
            name: a.name,
            code: a.code,
            description: a.description,
            enabled: a.enabled,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateAppRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    #[validate(length(min = 1, max = 64))]
    pub code: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateAppRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}
