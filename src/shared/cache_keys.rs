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
    pub const POLICY_PREFIX: &str = "abac:user_policies:";
    pub const SUBJECT_PREFIX: &str = "abac:user_attrs:";
    pub const APP_POLICY_VERSION_PREFIX: &str = "abac:app:policy_version:";
    pub const USER_VERSION_PREFIX: &str = "abac:user:version:";

    pub fn policy_key(
        user_id: uuid::Uuid,
        app_id: Option<uuid::Uuid>,
        app_policy_version: &str,
        user_version: &str,
    ) -> String {
        match app_id {
            Some(aid) => {
                format!("{POLICY_PREFIX}{user_id}:{aid}:{app_policy_version}:{user_version}")
            }
            None => format!("{POLICY_PREFIX}{user_id}::{app_policy_version}:{user_version}"),
        }
    }

    pub fn policy_version_key(user_id: uuid::Uuid, app_id: Option<uuid::Uuid>) -> String {
        match app_id {
            Some(aid) => format!("{POLICY_PREFIX}{user_id}:{aid}:pv"),
            None => format!("{POLICY_PREFIX}{user_id}:pv"),
        }
    }

    pub fn subject_key(user_id: uuid::Uuid, user_version: &str) -> String {
        format!("{SUBJECT_PREFIX}{user_id}:{user_version}")
    }

    pub fn subject_version_key(user_id: uuid::Uuid) -> String {
        format!("{USER_VERSION_PREFIX}{user_id}")
    }

    pub fn app_policy_version_key(app_id: Option<uuid::Uuid>) -> String {
        match app_id {
            Some(aid) => format!("{APP_POLICY_VERSION_PREFIX}{aid}"),
            None => format!("{APP_POLICY_VERSION_PREFIX}global"),
        }
    }

    pub fn user_version_key(user_id: uuid::Uuid) -> String {
        format!("{USER_VERSION_PREFIX}{user_id}")
    }
}
