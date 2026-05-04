use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::app::dto as domain;

#[derive(Debug, Serialize, ToSchema)]
pub struct AppDTO {
    pub id: Uuid,
    pub name: String,
    pub code: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<domain::AppDTO> for AppDTO {
    fn from(d: domain::AppDTO) -> Self {
        Self {
            id: d.id,
            name: d.name,
            code: d.code,
            description: d.description,
            enabled: d.enabled,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAppRequest {
    pub name: String,
    pub code: String,
    pub description: Option<String>,
}

impl From<CreateAppRequest> for domain::CreateAppRequest {
    fn from(r: CreateAppRequest) -> Self {
        Self {
            name: r.name,
            code: r.code,
            description: r.description,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAppRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}
