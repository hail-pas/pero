use serde::Deserialize;

use crate::db::entity::{apps, identity_provider_keys, identity_providers, oauth_clients, users};
use crate::web::util::UserInfo;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardLayout {
    pub user_username: String,
    pub user_name: String,
    pub user_avatar_url: String,
}

impl DashboardLayout {
    pub fn from_user(user: &users::Model) -> Self {
        let info = UserInfo::from_user(user);
        Self {
            user_username: info.username,
            user_name: info.name,
            user_avatar_url: info.avatar_url,
        }
    }
}

// === Forbidden ===

#[derive(Debug, serde::Serialize)]
pub struct ForbiddenView {
    pub code: String,
}

// === App List ===

#[derive(Debug, serde::Serialize)]
pub struct AppListView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub apps: Vec<AppSummary>,
    pub page: u64,
    pub total_pages: u64,
    pub q: String,
    pub status_filter: String,
    pub type_filter: String,
}

// === App Form ===

#[derive(Debug, serde::Serialize)]
pub struct AppFormView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub mode: String,
    pub app_id: String,
    pub form: AppFormData,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct AppFormData {
    #[serde(default)]
    pub csrf_token: String,
    pub code: String,
    pub name: String,
    pub app_type: String,
    pub description: String,
    pub homepage_url: String,
    pub logo_url: String,
}

// === App Detail ===

#[derive(Debug, serde::Serialize)]
pub struct AppDetailView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub app: AppSummary,
    pub clients: Vec<ClientSummary>,
    pub error: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateClientForm {
    pub app_id: uuid::Uuid,
    pub identifier: String,
    #[serde(default)]
    pub csrf_token: String,
    pub client_type: String,
    pub secret: String,
    pub name: String,
    pub redirect_uris: String,
    pub post_logout_redirect_uris: String,
    pub scopes: String,
    pub grant_types: String,
    #[serde(default)]
    pub require_pkce: bool,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: i32,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: i32,
    #[serde(default = "default_id_token_ttl")]
    pub id_token_ttl: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettingsForm {
    #[serde(default)]
    pub csrf_token: String,
    pub client_type: String,
    pub secret: String,
    pub name: String,
    pub redirect_uris: String,
    pub post_logout_redirect_uris: String,
    pub scopes: String,
    pub grant_types: String,
    #[serde(default)]
    pub require_pkce: bool,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: i32,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: i32,
    #[serde(default = "default_id_token_ttl")]
    pub id_token_ttl: i32,
}

impl From<CreateClientForm> for ClientSettingsForm {
    fn from(form: CreateClientForm) -> Self {
        Self {
            csrf_token: form.csrf_token,
            client_type: form.client_type,
            secret: form.secret,
            name: form.name,
            redirect_uris: form.redirect_uris,
            post_logout_redirect_uris: form.post_logout_redirect_uris,
            scopes: form.scopes,
            grant_types: form.grant_types,
            require_pkce: form.require_pkce,
            access_token_ttl: form.access_token_ttl,
            refresh_token_ttl: form.refresh_token_ttl,
            id_token_ttl: form.id_token_ttl,
        }
    }
}

const fn default_access_token_ttl() -> i32 {
    7200
}
const fn default_refresh_token_ttl() -> i32 {
    2592000
}
const fn default_id_token_ttl() -> i32 {
    7200
}

// === User List ===

#[derive(Debug, serde::Serialize)]
pub struct UserListView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub users: Vec<UserSummary>,
    pub page: u64,
    pub total_pages: u64,
    pub q: String,
    pub status_filter: String,
}

// === User Form ===

#[derive(Debug, serde::Serialize)]
pub struct UserFormView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub mode: String,
    pub user_id: String,
    pub form: UserFormData,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct UserFormData {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub username: String,
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub avatar_url: String,
}

// === User Detail ===

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserAccessRow {
    pub app_id: uuid::Uuid,
    pub app_code: String,
    pub app_name: String,
    pub status: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserIdentityRow {
    pub id: uuid::Uuid,
    pub kind: String,
    pub provider_name: String,
    pub provider_code: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, serde::Serialize)]
pub struct UserDetailView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub user: UserSummary,
    pub identities: Vec<UserIdentityRow>,
    pub access_list: Vec<UserAccessRow>,
    pub all_apps: Vec<(uuid::Uuid, String, String)>,
    pub error: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct UserStatusForm {
    #[serde(default)]
    pub csrf_token: String,
    pub status: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct ResetPasswordForm {
    #[serde(default)]
    pub csrf_token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct GrantAppForm {
    #[serde(default)]
    pub csrf_token: String,
    pub app_id: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct RevokeAppForm {
    #[serde(default)]
    pub csrf_token: String,
    pub app_id: String,
}

// === Provider List ===

#[derive(Debug, serde::Serialize)]
pub struct ProviderListView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub providers: Vec<ProviderSummary>,
    pub page: u64,
    pub total_pages: u64,
}

// === Provider Form ===

#[derive(Debug, serde::Serialize)]
pub struct ProviderFormView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub mode: String,
    pub provider_id: String,
    pub form: ProviderFormData,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct ProviderFormData {
    #[serde(default)]
    pub csrf_token: String,
    pub code: String,
    pub name: String,
    pub kind: String,
    pub icon: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub settings: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_registration: bool,
}

// === Provider Detail ===

#[derive(Debug, serde::Serialize)]
pub struct ProviderDetailView {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub provider: ProviderSummary,
    pub keys: Vec<KeySummary>,
    pub error: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct KeyForm {
    #[serde(default)]
    pub csrf_token: String,
    pub kid: String,
    pub algorithm: String,
    #[serde(default = "signing_key_use")]
    pub key_use: String,
    pub public_key_pem: String,
    pub private_key_pem: String,
    pub certificate_pem: String,
    #[serde(default)]
    pub active: bool,
    pub not_before: String,
    pub expires_at: String,
}

fn signing_key_use() -> String {
    "sig".to_owned()
}

#[derive(Debug, serde::Serialize)]
pub struct ClientSummary {
    pub id: uuid::Uuid,
    pub identifier: String,
    pub name: Option<String>,
    pub r#type: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub require_pkce: bool,
    pub access_token_ttl_seconds: i32,
    pub refresh_token_ttl_seconds: i32,
    pub id_token_ttl_seconds: i32,
    pub status: String,
}

impl From<oauth_clients::Model> for ClientSummary {
    fn from(model: oauth_clients::Model) -> Self {
        Self {
            id: model.id,
            identifier: model.identifier,
            name: model.name,
            r#type: model.r#type.to_string(),
            redirect_uris: model.redirect_uris,
            post_logout_redirect_uris: model.post_logout_redirect_uris,
            scopes: model.scopes,
            grant_types: model.grant_types,
            require_pkce: model.require_pkce,
            access_token_ttl_seconds: model.access_token_ttl_seconds,
            refresh_token_ttl_seconds: model.refresh_token_ttl_seconds,
            id_token_ttl_seconds: model.id_token_ttl_seconds,
            status: model.status.to_string(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ProviderSummary {
    pub id: uuid::Uuid,
    pub code: String,
    pub name: String,
    pub kind: String,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

impl From<identity_providers::Model> for ProviderSummary {
    fn from(model: identity_providers::Model) -> Self {
        Self {
            id: model.id,
            code: model.code,
            name: model.name,
            kind: model.kind.to_string(),
            issuer: model.issuer,
            client_id: model.client_id,
            enabled: model.enabled,
            created_at: model.created_at,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct KeySummary {
    pub id: uuid::Uuid,
    pub kid: String,
    pub algorithm: String,
    pub active: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<time::OffsetDateTime>,
}

impl From<identity_provider_keys::Model> for KeySummary {
    fn from(model: identity_provider_keys::Model) -> Self {
        Self {
            id: model.id,
            kid: model.kid,
            algorithm: model.algorithm.to_string(),
            active: model.active,
            revoked_at: model.revoked_at,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct AppSummary {
    pub id: uuid::Uuid,
    pub code: String,
    pub name: String,
    pub r#type: String,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub logo_url: Option<String>,
    pub status: String,
    pub system: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

impl From<apps::Model> for AppSummary {
    fn from(model: apps::Model) -> Self {
        Self {
            id: model.id,
            code: model.code,
            name: model.name,
            r#type: model.r#type.to_string(),
            description: model.description,
            homepage_url: model.homepage_url,
            logo_url: model.logo_url,
            status: model.status.to_string(),
            system: model.system,
            created_at: model.created_at,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct UserSummary {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

impl From<users::Model> for UserSummary {
    fn from(model: users::Model) -> Self {
        Self {
            id: model.id,
            username: model.username,
            email: model.email,
            phone: model.phone,
            nickname: model.nickname,
            avatar_url: model.avatar_url,
            status: model.status.to_string(),
            created_at: model.created_at,
        }
    }
}
