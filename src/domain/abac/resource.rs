use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum Resource {
    User,
    App,
    OAuth2Client,
    Policy,
    SocialProvider,
    UserInfo,
    Evaluate,
    Other(String),
}

impl Resource {
    pub fn from_path(path: &str) -> Self {
        if path.starts_with("/api/users") {
            Resource::User
        } else if path.starts_with("/api/apps") {
            Resource::App
        } else if path.starts_with("/api/oauth2/clients") {
            Resource::OAuth2Client
        } else if path.starts_with("/api/policies") {
            Resource::Policy
        } else if path.starts_with("/api/social-providers") {
            Resource::SocialProvider
        } else if path.starts_with("/oauth2/userinfo") {
            Resource::UserInfo
        } else if path.starts_with("/api/abac/evaluate") {
            Resource::Evaluate
        } else {
            Resource::Other(path.to_string())
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Resource::User => "user",
            Resource::App => "app",
            Resource::OAuth2Client => "oauth2_client",
            Resource::Policy => "policy",
            Resource::SocialProvider => "social_provider",
            Resource::UserInfo => "userinfo",
            Resource::Evaluate => "evaluate",
            Resource::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    List,
    Assign,
    Unassign,
    Other(String),
}

impl Action {
    pub fn from_method_and_path(method: &str, path: &str) -> Self {
        match (method, path) {
            ("POST", p) if p.contains("/assign") => Action::Assign,
            ("DELETE", p) if p.contains("/policies") => Action::Unassign,
            ("POST", _) => Action::Create,
            ("GET", p) => {
                if !p.contains("/{")
                    && (p.ends_with("s")
                        || (p.contains("/users") && !matches_resource_id(p)))
                {
                    Action::List
                } else {
                    Action::Read
                }
            }
            ("PUT", _) => Action::Update,
            ("DELETE", _) => Action::Delete,
            _ => Action::Other(method.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::List => "list",
            Action::Assign => "assign",
            Action::Unassign => "unassign",
            Action::Other(s) => s.as_str(),
        }
    }
}

fn matches_resource_id(path: &str) -> bool {
    path.matches('/').count() > 3
}
