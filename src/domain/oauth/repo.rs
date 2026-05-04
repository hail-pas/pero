use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::oauth::entity::{TokenFamily, UserAuthorization};
use crate::domain::oauth::models::{
    AuthorizationCode, CreateClientRequest, OAuth2Client, RefreshToken, UpdateClientRequest,
};
use crate::shared::error::AppError;

pub struct CreateAuthCodeParams {
    pub code: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub sid: Option<String>,
    pub auth_time: i64,
    pub ttl_minutes: i64,
}

pub struct AccessTokenParams {
    pub sub: String,
    pub roles: Vec<String>,
    pub scope: Option<String>,
    pub azp: Option<String>,
    pub app_id: Option<String>,
    pub sid: Option<String>,
    pub ttl_minutes: i64,
}

#[async_trait]
pub trait OAuth2ClientStore: Send + Sync {
    async fn create(
        &self,
        client_id: &str,
        client_secret_hash: &str,
        req: &CreateClientRequest,
    ) -> Result<OAuth2Client, AppError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<OAuth2Client>, AppError>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuth2Client>, AppError>;
    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<OAuth2Client>, i64), AppError>;
    async fn update(&self, id: Uuid, req: &UpdateClientRequest) -> Result<OAuth2Client, AppError>;
    async fn delete(&self, id: Uuid) -> Result<(), AppError>;
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    async fn create_auth_code(
        &self,
        params: CreateAuthCodeParams,
    ) -> Result<AuthorizationCode, AppError>;
    async fn find_active_auth_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, AppError>;
    async fn consume_auth_code(&self, code: &str) -> Result<bool, AppError>;
    async fn purge_expired_auth_codes(&self) -> Result<u64, AppError>;
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn create_refresh_token(
        &self,
        client_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
        family_id: Option<Uuid>,
    ) -> Result<RefreshToken, AppError>;
    async fn find_active_refresh_for_update(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError>;
    async fn revoke_refresh(&self, id: Uuid) -> Result<(), AppError>;
    async fn find_revoked_by_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError>;
    async fn revoke_all_for_user_client(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<(), AppError>;
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), AppError>;
    async fn list_active_by_user(&self, user_id: Uuid) -> Result<Vec<UserAuthorization>, AppError>;
    async fn revoke_for_user(&self, id: Uuid, user_id: Uuid) -> Result<(), AppError>;
    async fn exchange_auth_code(
        &self,
        code: &str,
        client_id: Uuid,
        user_id: Uuid,
        scopes: &[String],
        auth_time: i64,
        refresh_ttl_days: i64,
    ) -> Result<(AuthorizationCode, Option<String>), AppError>;
    async fn rotate_refresh_token(
        &self,
        old_token: &str,
        client_id: Uuid,
        user_id: Uuid,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
        family_id: Option<Uuid>,
    ) -> Result<(RefreshToken, Option<String>), AppError>;
    async fn revoke_token_if_owned(&self, token: &str, client_id: Uuid) -> Result<(), AppError>;
    async fn purge_expired_tokens(&self) -> Result<u64, AppError>;
}

#[async_trait]
pub trait TokenFamilyStore: Send + Sync {
    async fn create_token_family(
        &self,
        client_id: Uuid,
        user_id: Uuid,
    ) -> Result<TokenFamily, AppError>;
    async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), AppError>;
}

#[async_trait]
pub trait TokenSigner: Send + Sync {
    fn sign_access_token(&self, params: AccessTokenParams) -> Result<String, AppError>;
    fn sign_id_token(
        &self,
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
        iat: i64,
        auth_time: i64,
        nonce: Option<String>,
        name: Option<String>,
        nickname: Option<String>,
        picture: Option<String>,
        email: Option<String>,
        email_verified: Option<bool>,
        phone_number: Option<String>,
        phone_number_verified: Option<bool>,
        sid: Option<String>,
    ) -> Result<String, AppError>;
    fn issuer(&self) -> &str;
}
