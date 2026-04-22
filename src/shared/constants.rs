pub mod headers {
    pub const X_REQUEST_ID: &str = "x-request-id";
    pub const X_APP_ID: &str = "x-app-id";
}

pub mod cache_keys {
    pub const REFRESH_TOKEN_PREFIX: &str = "refresh_token:";
    pub const REFRESH_TOKEN_PREV_PREFIX: &str = "refresh_token_prev:";
    pub const ABAC_PREFIX: &str = "abac:";
    pub const PASSWORD_RESET_PREFIX: &str = "password_reset:";
}

pub mod identity {
    pub const PROVIDER_PASSWORD: &str = "password";
    pub const DEFAULT_ROLE: &str = "user";
    pub const ROLE_ATTR_KEY: &str = "role";
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
