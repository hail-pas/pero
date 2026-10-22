use askama::Template;
use serde::Deserialize;

use crate::db::entity::{apps, identity_provider_keys, identity_providers, oauth_clients, users};
use crate::web::util::UserInfo;

#[derive(Debug, Clone)]
pub struct DashboardLayout {
    pub user_username: String,
    pub user_name: String,
    pub user_avatar_url: String,
    pub user_initial: String,
    pub active: &'static str,
}

impl DashboardLayout {
    pub fn from_user(user: &users::Model, active: &'static str) -> Self {
        let info = UserInfo::from_user(user);
        Self {
            user_username: info.username,
            user_name: info.name,
            user_avatar_url: info.avatar_url,
            user_initial: info.initial,
            active,
        }
    }
}

// === Forbidden ===

#[derive(Debug, Template)]
#[template(path = "dashboard/forbidden.html")]
pub struct ForbiddenTemplate {
    pub code: String,
}

// === App List ===

#[derive(Debug, Template)]
#[template(path = "dashboard/app_list.html")]
pub struct AppListTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub apps: Vec<apps::Model>,
    pub page: u64,
    pub total_pages: u64,
    pub q: String,
    pub status_filter: String,
    pub type_filter: String,
}

// === App Form ===

#[derive(Debug, Template)]
#[template(path = "dashboard/app_form.html")]
pub struct AppFormTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub mode: String,
    pub app_id: String,
    pub form: AppFormData,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AppFormData {
    #[serde(default)]
    pub csrf_token: String,
    pub code: String,
    pub name: String,
    pub app_type: String,
    pub description: String,
    pub homepage_url: String,
    pub logo_url: String,
    pub auto_access: Option<String>,
}

// === App Detail ===

#[derive(Debug, Template)]
#[template(path = "dashboard/app_detail.html")]
pub struct AppDetailTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub app: apps::Model,
    pub clients: Vec<oauth_clients::Model>,
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub app_id: String,
    pub identifier: String,
    pub client_type: String,
    pub secret: String,
    pub name: String,
    pub redirect_uris: String,
    pub post_logout_redirect_uris: String,
    pub scopes: String,
    pub grant_types: String,
    pub require_pkce: Option<String>,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: i32,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: i32,
    #[serde(default = "default_id_token_ttl")]
    pub id_token_ttl: i32,
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

#[derive(Debug, Template)]
#[template(path = "dashboard/user_list.html")]
pub struct UserListTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub users: Vec<users::Model>,
    pub page: u64,
    pub total_pages: u64,
    pub q: String,
    pub status_filter: String,
}

// === User Form ===

#[derive(Debug, Template)]
#[template(path = "dashboard/user_form.html")]
pub struct UserFormTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub mode: String,
    pub user_id: String,
    pub form: UserFormData,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserFormData {
    #[serde(default)]
    pub csrf_token: String,
    pub username: String,
    pub email: String,
    pub phone: String,
    pub nickname: String,
    pub avatar_url: String,
    #[serde(default)]
    pub password: String,
}

// === User Detail ===

#[derive(Debug, Clone)]
pub struct UserAccessRow {
    pub app_id: uuid::Uuid,
    pub app_code: String,
    pub app_name: String,
    pub status: crate::db::enums::CommonStatus,
}

#[derive(Debug, Clone)]
pub struct UserIdentityRow {
    pub id: uuid::Uuid,
    pub kind: crate::db::enums::IdentityKind,
    pub provider_name: String,
    pub provider_code: String,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Template)]
#[template(path = "dashboard/user_detail.html")]
pub struct UserDetailTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub user: users::Model,
    pub identities: Vec<UserIdentityRow>,
    pub access_list: Vec<UserAccessRow>,
    pub all_apps: Vec<(uuid::Uuid, String, String)>,
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct UserStatusForm {
    #[serde(default)]
    pub csrf_token: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordForm {
    #[serde(default)]
    pub csrf_token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct GrantAppForm {
    #[serde(default)]
    pub csrf_token: String,
    pub app_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeAppForm {
    #[serde(default)]
    pub csrf_token: String,
    pub app_id: String,
}

// === Provider List ===

#[derive(Debug, Template)]
#[template(path = "dashboard/provider_list.html")]
pub struct ProviderListTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub providers: Vec<identity_providers::Model>,
    pub page: u64,
    pub total_pages: u64,
}

// === Provider Form ===

#[derive(Debug, Template)]
#[template(path = "dashboard/provider_form.html")]
pub struct ProviderFormTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub mode: String,
    pub provider_id: String,
    pub form: ProviderFormData,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
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
    pub enabled: Option<String>,
}

// === Provider Detail ===

#[derive(Debug, Template)]
#[template(path = "dashboard/provider_detail.html")]
pub struct ProviderDetailTemplate {
    pub layout: DashboardLayout,
    pub csrf_token: String,
    pub provider: identity_providers::Model,
    pub keys: Vec<identity_provider_keys::Model>,
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyForm {
    #[serde(default)]
    pub csrf_token: String,
    pub kid: String,
    pub algorithm: String,
    pub key_use: String,
    pub public_key_pem: String,
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub active: Option<String>,
    pub not_before: String,
    pub expires_at: String,
}
