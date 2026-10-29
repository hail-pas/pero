use pero_cache_redis::cache_key_specs;
use serde::{Deserialize, Serialize};

cache_key_specs! {
    error = pero_error::AppError;

    pub integration_test: IntegrationTestKey => IntegrationTestValue {
        pattern: "integration_test:{hash}", ttl: 600, args: (hash: &str),
    }

    pub mfa_attempt: MfaAttemptKey => u32 { pattern: "mfa_attempt:{user}", ttl: 300, args: (user: &str), }

    pub pending_req: PendingReqKey => PendingReqValue {
        pattern: "pending_req:{nonce}",
        ttl: 600,
        args: (nonce: &str),
    }

    pub social_state: SocialStateKey => SocialStateValue {
        pattern: "social:{state_hash}",
        ttl: 600,
        args: (state_hash: &str),
    }

    pub social_link: SocialLinkKey => SocialLinkValue {
        pattern: "social_link:{nonce}",
        ttl: 600,
        args: (nonce: &str),
    }


}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReqValue {
    pub auth_request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialStateValue {
    #[serde(default)]
    pub reauth_session: Option<uuid::Uuid>,
    pub redirect: String,
    #[serde(default)]
    pub auth_request_id: Option<String>,
    #[serde(default)]
    pub account_link: Option<(uuid::Uuid, uuid::Uuid)>,
    pub provider_id: String,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub reauthenticate_after: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialLinkValue {
    pub redirect: String,
    #[serde(default)]
    pub auth_request_id: Option<String>,
    pub user_id: String,
    pub provider_id: String,
    pub provider_code: String,
    pub provider_name: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IntegrationTestValue {
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub app_id: uuid::Uuid,
    pub client_id: uuid::Uuid,
    pub verifier: String,
    pub nonce: String,
    pub code: Option<String>,
}
