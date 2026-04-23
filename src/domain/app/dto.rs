use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::domain::app::entity::App;

#[derive(Debug, Serialize, Clone, ToSchema)]
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

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateAppRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    #[validate(length(min = 1, max = 64), custom(function = "validate_app_code"))]
    pub code: String,
    #[validate(length(max = 512))]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateAppRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: Option<String>,
    #[validate(length(max = 512))]
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

fn validate_app_code(code: &str) -> Result<(), validator::ValidationError> {
    for c in code.chars() {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' && c != '_' {
            return Err(validator::ValidationError::new("invalid_app_code"));
        }
    }
    Ok(())
}
