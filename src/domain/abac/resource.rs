use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resource {
    Api,
    Type(String),
}

impl Resource {
    pub fn custom(value: impl Into<String>) -> Self {
        Resource::Type(value.into())
    }

    pub fn is_valid_label(value: &str) -> bool {
        value == "api" || is_custom_label(value)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Resource::Api => "api",
            Resource::Type(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Type(String),
}

impl Action {
    pub fn custom(value: impl Into<String>) -> Self {
        Action::Type(value.into())
    }

    pub fn from_http_method(method: &str) -> Self {
        match method.to_ascii_uppercase().as_str() {
            "GET" => Action::Get,
            "POST" => Action::Post,
            "PUT" => Action::Put,
            "PATCH" => Action::Patch,
            "DELETE" => Action::Delete,
            "HEAD" => Action::Head,
            "OPTIONS" => Action::Options,
            _ => Action::custom(method.to_ascii_lowercase()),
        }
    }

    pub fn is_valid_label(value: &str) -> bool {
        matches!(
            value,
            "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
        ) || is_custom_label(value)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Action::Get => "get",
            Action::Post => "post",
            Action::Put => "put",
            Action::Patch => "patch",
            Action::Delete => "delete",
            Action::Head => "head",
            Action::Options => "options",
            Action::Type(s) => s.as_str(),
        }
    }
}

fn is_custom_label(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | ':'))
}
