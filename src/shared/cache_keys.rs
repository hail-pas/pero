pub mod social {
    pub const STATE_PREFIX: &str = "social_state:";
    pub const STATE_TTL: i64 = 600;

    pub fn state_key(token: &str) -> String {
        format!("{STATE_PREFIX}{token}")
    }
}

pub mod sso {
    pub const SESSION_PREFIX: &str = "sso_session:";

    pub fn session_key(id: &str) -> String {
        format!("{SESSION_PREFIX}{id}")
    }
}

pub mod identity_session {
    pub const SESSION_PREFIX: &str = "identity_session:";
    pub const USER_SESSIONS_PREFIX: &str = "identity_user_sessions:";

    pub fn session_key(id: &str) -> String {
        format!("{SESSION_PREFIX}{id}")
    }

    pub fn user_sessions_key(user_id: uuid::Uuid) -> String {
        format!("{USER_SESSIONS_PREFIX}{user_id}")
    }
}

pub mod abac {
    pub const POLICY_PREFIX: &str = "abac:";
    pub const SUBJECT_PREFIX: &str = "abac_subject:";

    pub fn policy_key(user_id: uuid::Uuid, app_id: Option<uuid::Uuid>) -> String {
        match app_id {
            Some(aid) => format!("{POLICY_PREFIX}{user_id}:{aid}"),
            None => format!("{POLICY_PREFIX}{user_id}:"),
        }
    }

    pub fn policy_version_key(user_id: uuid::Uuid, app_id: Option<uuid::Uuid>) -> String {
        format!(
            "{POLICY_PREFIX}{user_id}:{}:v",
            app_id.map(|id| id.to_string()).unwrap_or_default()
        )
    }

    pub fn subject_key(user_id: uuid::Uuid) -> String {
        format!("{SUBJECT_PREFIX}{user_id}")
    }

    pub fn subject_version_key(user_id: uuid::Uuid) -> String {
        format!("{SUBJECT_PREFIX}{user_id}:sv")
    }

    pub fn app_version_key(app_id: Option<uuid::Uuid>) -> String {
        match app_id {
            Some(aid) => format!("{POLICY_PREFIX}app:{aid}:v"),
            None => format!("{POLICY_PREFIX}app::v"),
        }
    }
}
