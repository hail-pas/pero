use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::domain::abac::entity::{Policy, PolicyCondition, UserAttribute as AbacUserAttribute};
use crate::domain::app::entity::App;
use crate::domain::credential::entity::Identity;
use crate::domain::federation::entity::SocialProvider;
use crate::domain::oauth::entity::{
    AuthorizationCode, OAuth2Client, RefreshToken, TokenFamily, UserAuthorization,
};
use crate::domain::user::dto::UserAttribute;
use crate::domain::user::entity::User;

impl<'r> FromRow<'r, PgRow> for App {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            code: row.try_get("code")?,
            description: row.try_get("description")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for Policy {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            effect: row.try_get("effect")?,
            priority: row.try_get("priority")?,
            enabled: row.try_get("enabled")?,
            app_id: row.try_get("app_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for PolicyCondition {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            policy_id: row.try_get("policy_id")?,
            condition_type: row.try_get("condition_type")?,
            key: row.try_get("key")?,
            operator: row.try_get("operator")?,
            value: row.try_get("value")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for AbacUserAttribute {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            key: row.try_get("key")?,
            value: row.try_get("value")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for Identity {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            provider: row.try_get("provider")?,
            provider_uid: row.try_get("provider_uid")?,
            credential: row.try_get("credential")?,
            verified: row.try_get("verified")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for SocialProvider {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            display_name: row.try_get("display_name")?,
            client_id: row.try_get("client_id")?,
            client_secret: row.try_get("client_secret")?,
            authorize_url: row.try_get("authorize_url")?,
            token_url: row.try_get("token_url")?,
            userinfo_url: row.try_get("userinfo_url")?,
            scopes: row.try_get("scopes")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for OAuth2Client {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            app_id: row.try_get("app_id")?,
            client_id: row.try_get("client_id")?,
            client_secret_hash: row.try_get("client_secret_hash")?,
            client_name: row.try_get("client_name")?,
            redirect_uris: row.try_get("redirect_uris")?,
            grant_types: row.try_get("grant_types")?,
            scopes: row.try_get("scopes")?,
            post_logout_redirect_uris: row.try_get("post_logout_redirect_uris")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for AuthorizationCode {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            code: row.try_get("code")?,
            client_id: row.try_get("client_id")?,
            user_id: row.try_get("user_id")?,
            redirect_uri: row.try_get("redirect_uri")?,
            scopes: row.try_get("scopes")?,
            code_challenge: row.try_get("code_challenge")?,
            code_challenge_method: row.try_get("code_challenge_method")?,
            nonce: row.try_get("nonce")?,
            sid: row.try_get("sid")?,
            auth_time: row.try_get("auth_time")?,
            expires_at: row.try_get("expires_at")?,
            used: row.try_get("used")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for RefreshToken {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            client_id: row.try_get("client_id")?,
            user_id: row.try_get("user_id")?,
            refresh_token: row.try_get("refresh_token")?,
            scopes: row.try_get("scopes")?,
            auth_time: row.try_get("auth_time")?,
            expires_at: row.try_get("expires_at")?,
            revoked: row.try_get("revoked")?,
            created_at: row.try_get("created_at")?,
            family_id: row.try_get("family_id")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for UserAuthorization {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            client_name: row.try_get("client_name")?,
            scopes: row.try_get("scopes")?,
            created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
            token_id: row.try_get("token_id")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for TokenFamily {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            client_id: row.try_get("client_id")?,
            user_id: row.try_get("user_id")?,
            revoked: row.try_get("revoked")?,
            created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for User {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get::<Uuid, _>("id")?,
            username: row.try_get("username")?,
            email: row.try_get("email")?,
            phone: row.try_get("phone")?,
            nickname: row.try_get("nickname")?,
            avatar_url: row.try_get("avatar_url")?,
            email_verified: row.try_get("email_verified")?,
            phone_verified: row.try_get("phone_verified")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for UserAttribute {
    fn from_row(row: &'r PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            key: row.try_get("key")?,
            value: row.try_get("value")?,
        })
    }
}
