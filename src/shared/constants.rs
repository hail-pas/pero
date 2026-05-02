pub mod headers {
    pub const X_REQUEST_ID: &str = "x-request-id";
    pub const X_APP_ID: &str = "x-app-id";
    pub const X_PROCESS_TIME: &str = "x-process-time";
}

pub mod cookies {
    pub const SSO_SESSION: &str = "pero_sso_session";
    pub const ACCOUNT_TOKEN: &str = "pero_account_token";
    pub const LOCALE: &str = "pero_locale";
}

pub mod cache_keys {
    pub const REFRESH_TOKEN_PREFIX: &str = "refresh_token:";
    pub const REFRESH_TOKEN_PREV_PREFIX: &str = "refresh_token_prev:";
    pub const ABAC_PREFIX: &str = "abac:";
    pub const ABAC_SUBJECT_PREFIX: &str = "abac_subject:";
    pub const PASSWORD_RESET_PREFIX: &str = "password_reset:";
    pub const EMAIL_VERIFY_PREFIX: &str = "email_verify:";
    pub const PHONE_VERIFY_PREFIX: &str = "phone_verify:";
    pub const IDENTITY_SESSION_PREFIX: &str = "identity_session:";
    pub const IDENTITY_USER_SESSIONS_PREFIX: &str = "identity_user_sessions:";
    pub const SSO_SESSION_PREFIX: &str = "sso_session:";
    pub const CSRF_PREFIX: &str = "csrf:";
}

pub mod identity {
    pub const PROVIDER_PASSWORD: &str = "password";
    pub const DEFAULT_ROLE: &str = "user";
    pub const ROLE_ATTR_KEY: &str = "role";
}

pub mod security {
    pub const FAKE_BCRYPT_HASH: &str =
        "$2b$12$TrePSBin7KMS2YzgKJgNXeSKHaFjHOa/XYRm8kqDQoJHqWbsLCDKi";
}

pub mod oauth2 {
    pub const GRANT_TYPE_AUTH_CODE: &str = "authorization_code";
    pub const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";
    pub const RESPONSE_TYPE_CODE: &str = "code";
    pub const TOKEN_TYPE_BEARER: &str = "Bearer";
    pub const TOKEN_TYPE_BEARER_PREFIX: &str = "Bearer ";
    pub const PKCE_METHOD_S256: &str = "S256";

    pub mod scopes {
        pub const OPENID: &str = "openid";
        pub const PROFILE: &str = "profile";
        pub const EMAIL: &str = "email";
        pub const PHONE: &str = "phone";
    }
}

pub mod jwt {
    pub const ALG_RS256: &str = "RS256";
    pub const KEY_TYPE_RSA: &str = "RSA";
    pub const KEY_USE_SIG: &str = "sig";
    pub const ACCESS_TOKEN_AUDIENCE: &str = "pero-api";
}
