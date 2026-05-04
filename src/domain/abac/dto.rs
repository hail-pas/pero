use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationErrors};

use crate::shared::patch::FieldUpdate;
use crate::shared::validation;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Validate)]
pub struct CreatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
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

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    #[serde(default)]
    pub name: FieldUpdate<String>,
    #[serde(default)]
    pub description: FieldUpdate<String>,
    #[serde(default)]
    pub effect: FieldUpdate<PolicyEffect>,
    #[serde(default)]
    pub priority: FieldUpdate<i32>,
    #[serde(default)]
    pub enabled: FieldUpdate<bool>,
    #[serde(default)]
    pub app_id: FieldUpdate<Uuid>,
    #[serde(default)]
    pub conditions: FieldUpdate<Vec<CreateConditionRequest>>,
}

impl Validate for UpdatePolicyRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        self.name.reject_clear("name", &mut errors, |v| {
            validation::validate_length(v, 1, 128)
        });

        self.effect.reject_clear("effect", &mut errors, |_| Ok(()));
        self.priority
            .reject_clear("priority", &mut errors, |_| Ok(()));
        self.enabled
            .reject_clear("enabled", &mut errors, |_| Ok(()));

        self.conditions
            .reject_clear("conditions", &mut errors, |_| Ok(()));
        self.conditions.validate_nested("conditions", &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateConditionRequest {
    pub condition_type: ConditionType,
    #[validate(length(min = 1, max = 128))]
    pub key: String,
    pub operator: ConditionOperator,
    #[validate(length(min = 1, max = 1024))]
    pub value: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct EvaluateRequest {
    #[validate(length(min = 1, max = 512))]
    pub resource: String,
    #[validate(length(min = 1, max = 32))]
    pub action: String,
    pub app_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub allowed: bool,
    pub effect: String,
}

fn default_enabled() -> bool {
    true
}
