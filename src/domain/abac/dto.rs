use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    #[default]
    Allow,
    Deny,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyEffect::Allow => "allow",
            PolicyEffect::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConditionType {
    Subject,
    Resource,
    Action,
    App,
}

impl ConditionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConditionType::Subject => "subject",
            ConditionType::Resource => "resource",
            ConditionType::Action => "action",
            ConditionType::App => "app",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConditionOperator {
    Eq,
    In,
    Wildcard,
    Regex,
    Contains,
    Gt,
    Lt,
}

impl ConditionOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConditionOperator::Eq => "eq",
            ConditionOperator::In => "in",
            ConditionOperator::Wildcard => "wildcard",
            ConditionOperator::Regex => "regex",
            ConditionOperator::Contains => "contains",
            ConditionOperator::Gt => "gt",
            ConditionOperator::Lt => "lt",
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    pub description: Option<String>,
    pub effect: PolicyEffect,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    #[validate(nested)]
    pub conditions: Vec<CreateConditionRequest>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub effect: Option<PolicyEffect>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub app_id: Option<Uuid>,
    #[validate(nested)]
    pub conditions: Option<Vec<CreateConditionRequest>>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateConditionRequest {
    pub condition_type: ConditionType,
    #[validate(length(min = 1, max = 128))]
    pub key: String,
    pub operator: ConditionOperator,
    #[validate(length(min = 1, max = 1024))]
    pub value: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct EvaluateRequest {
    #[validate(length(min = 1, max = 512))]
    pub resource: String,
    #[validate(length(min = 1, max = 32))]
    pub action: String,
    pub app_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EvaluateResponse {
    pub allowed: bool,
    pub effect: String,
}

fn default_enabled() -> bool {
    true
}
