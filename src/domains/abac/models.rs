use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, sqlx::FromRow, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow, Serialize, Deserialize, Clone)]
pub struct PolicyCondition {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub condition_type: String,
    pub key: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct EvalContext {
    pub subject_attrs: Vec<(String, String)>,
    pub resource: String,
    pub action: String,
    pub app_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    pub conditions: Vec<CreateConditionRequest>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub app_id: Option<Uuid>,
    pub conditions: Option<Vec<CreateConditionRequest>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateConditionRequest {
    pub condition_type: String,
    #[validate(length(min = 1, max = 128))]
    pub key: String,
    pub operator: String,
    pub value: String,
}

fn default_enabled() -> bool {
    true
}
