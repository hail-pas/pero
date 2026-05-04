use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::abac::service as svc;

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyConditionDTO {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub condition_type: String,
    pub key: String,
    pub operator: String,
    pub value: String,
}

impl From<crate::domain::abac::entity::PolicyCondition> for PolicyConditionDTO {
    fn from(c: crate::domain::abac::entity::PolicyCondition) -> Self {
        Self {
            id: c.id,
            policy_id: c.policy_id,
            condition_type: c.condition_type,
            key: c.key,
            operator: c.operator,
            value: c.value,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyDTO {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub conditions: Vec<PolicyConditionDTO>,
}

impl From<svc::PolicyDTO> for PolicyDTO {
    fn from(d: svc::PolicyDTO) -> Self {
        Self {
            id: d.id,
            name: d.name,
            description: d.description,
            effect: d.effect,
            priority: d.priority,
            enabled: d.enabled,
            app_id: d.app_id,
            created_at: d.created_at,
            updated_at: d.updated_at,
            conditions: d.conditions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
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

fn default_enabled() -> bool {
    true
}

impl From<CreatePolicyRequest> for crate::domain::abac::dto::CreatePolicyRequest {
    fn from(r: CreatePolicyRequest) -> Self {
        use crate::domain::abac::dto::*;
        let effect = match r.effect.as_str() {
            "deny" => PolicyEffect::Deny,
            _ => PolicyEffect::Allow,
        };
        Self {
            name: r.name,
            description: r.description,
            effect,
            priority: r.priority,
            enabled: r.enabled,
            app_id: r.app_id,
            conditions: r.conditions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub app_id: Option<Uuid>,
    pub conditions: Option<Vec<CreateConditionRequest>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConditionRequest {
    pub condition_type: String,
    pub key: String,
    pub operator: String,
    pub value: String,
}

impl From<CreateConditionRequest> for crate::domain::abac::dto::CreateConditionRequest {
    fn from(r: CreateConditionRequest) -> Self {
        use crate::domain::abac::dto::*;
        let condition_type = match r.condition_type.as_str() {
            "resource" => ConditionType::Resource,
            "action" => ConditionType::Action,
            "app" => ConditionType::App,
            _ => ConditionType::Subject,
        };
        let operator = match r.operator.as_str() {
            "in" => ConditionOperator::In,
            "wildcard" => ConditionOperator::Wildcard,
            "regex" => ConditionOperator::Regex,
            "contains" => ConditionOperator::Contains,
            "gt" => ConditionOperator::Gt,
            "lt" => ConditionOperator::Lt,
            _ => ConditionOperator::Eq,
        };
        Self {
            condition_type,
            key: r.key,
            operator,
            value: r.value,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EvaluateRequest {
    pub resource: String,
    pub action: String,
    pub app_id: Option<Uuid>,
}

impl From<EvaluateRequest> for crate::domain::abac::dto::EvaluateRequest {
    fn from(r: EvaluateRequest) -> Self {
        Self {
            resource: r.resource,
            action: r.action,
            app_id: r.app_id,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EvaluateResponse {
    pub allowed: bool,
    pub effect: String,
}

impl From<crate::domain::abac::dto::EvaluateResponse> for EvaluateResponse {
    fn from(d: crate::domain::abac::dto::EvaluateResponse) -> Self {
        Self {
            allowed: d.allowed,
            effect: d.effect,
        }
    }
}
