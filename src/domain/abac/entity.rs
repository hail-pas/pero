use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::resource::{Action, Resource};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyCondition {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub condition_type: String,
    pub key: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug)]
pub struct UserAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteScope {
    Admin,
    App,
}

#[derive(Debug, Clone)]
pub struct EvalContext {
    pub subject_attrs: HashMap<String, Vec<String>>,
    pub resource: String,
    pub action: String,
    pub domain_resource: Option<Resource>,
    pub domain_action: Option<Action>,
    pub app_id: Option<Uuid>,
    pub route_scope: RouteScope,
}
