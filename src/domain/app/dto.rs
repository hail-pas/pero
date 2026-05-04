use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationErrors};

use crate::domain::app::entity::App;
use crate::shared::patch::FieldUpdate;
use crate::shared::validation;

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
    #[validate(length(min = 1, max = 64), custom(function = "validate_app_code"))]
    pub code: String,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(length(max = 512))]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAppRequest {
    #[serde(default)]
    pub name: FieldUpdate<String>,
    #[serde(default)]
    pub description: FieldUpdate<String>,
    #[serde(default)]
    pub enabled: FieldUpdate<bool>,
}

impl Validate for UpdateAppRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        self.name.reject_clear("name", &mut errors, |v| {
            validation::validate_length(v, 1, 128)
        });

        self.description.validate("description", &mut errors, |v| {
            validation::validate_length(v, 0, 512)
        });
        self.enabled
            .reject_clear("enabled", &mut errors, |_| Ok(()));

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn validate_app_code(code: &str) -> Result<(), validator::ValidationError> {
    for c in code.chars() {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' && c != '_' {
            return Err(validator::ValidationError::new("invalid_app_code"));
        }
    }
    Ok(())
}
