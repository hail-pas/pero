use askama::Template;
use pero_utils::string::normalize_optional_string;
use serde::Deserialize;

use crate::web::sso::utility::empty_string_as_none;

/// 社交登录 Provider 信息（传递给模板）
#[derive(Debug, Clone)]
pub struct SocialProvider {
    pub key: String,
    pub name: String,
    pub icon: String,
}

/// 登录页模板
#[derive(Debug, Template)]
#[template(path = "sso/login.html")]
pub struct LoginTemplate {
    pub error: String,
    pub providers: Vec<SocialProvider>,
    pub csrf_token: String,
}

/// EP-03: POST /sso/login 表单
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    pub csrf_token: String,
    pub identifier_type: String,
    pub identifier: String,
    pub password: String,
    pub remember_me: Option<String>,
    #[serde(default)]
    pub redirect: String,
}

/// 注册页模板
#[derive(Debug, Template)]
#[template(path = "sso/register.html")]
pub struct RegisterTemplate {
    pub error: String,
    pub csrf_token: String,
}

/// EP-05: POST /sso/register 表单
#[derive(Debug, Deserialize, validator::Validate)]
pub struct RegisterForm {
    #[serde(default)]
    pub csrf_token: String,
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    #[validate(email)]
    pub email: Option<String>,
    pub password: String,
    pub nickname: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub phone: Option<String>,
}

impl RegisterForm {
    pub fn normalize_optional_fields(&mut self) {
        self.email = normalize_optional_string(self.email.take());
        self.nickname = normalize_optional_string(self.nickname.take());
        self.phone = normalize_optional_string(self.phone.take());
    }
}

/// 忘记密码页模板
#[derive(Debug, Template)]
#[template(path = "sso/forgot_password.html")]
pub struct ForgotPasswordTemplate {
    pub error: String,
    pub success: bool,
    pub csrf_token: String,
}

/// EP-07: POST /sso/forgot-password 表单
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordForm {
    #[serde(default)]
    pub csrf_token: String,
    pub identifier: String,
}

/// 重置密码页模板
#[derive(Debug, Template)]
#[template(path = "sso/reset_password.html")]
pub struct ResetPasswordTemplate {
    pub token: String,
    pub error: String,
    pub success: String,
    pub csrf_token: String,
}

/// EP-09: POST /sso/reset-password 表单
#[derive(Debug, Deserialize)]
pub struct ResetPasswordForm {
    #[serde(default)]
    pub csrf_token: String,
    pub new_password: String,
    pub confirm_password: String,
}

/// 授权确认页模板
#[derive(Debug, Template)]
#[template(path = "sso/authorization.html")]
pub struct ConsentTemplate {
    pub csrf_token: String,
    pub client_name: String,
    pub client_url: String,
    pub scopes: Vec<String>,
    pub user_name: String,
    pub user_email: String,
    pub user_avatar_url: String,
    pub user_initial: String,
}

/// EP-11: POST /sso/consent 表单
#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub action: String,
    pub csrf_token: String,
}

/// 错误页模板
#[derive(Debug, Template)]
#[template(path = "sso/error.html")]
pub struct ErrorTemplate {
    pub code: String,
}

/// 社交登录命中已有账号后的确认关联页
#[derive(Debug, Template)]
#[template(path = "sso/social_link.html")]
pub struct SocialLinkTemplate {
    pub csrf_token: String,
    pub nonce: String,
    pub provider_name: String,
    pub account_email: String,
    pub display_name: String,
    pub error: String,
}

/// POST /sso/social/link 表单
#[derive(Debug, Deserialize)]
pub struct SocialLinkForm {
    pub csrf_token: String,
    pub nonce: String,
    pub password: String,
}

/// 退出确认页模板
#[derive(Debug, Template)]
#[template(path = "oidc/end_session.html")]
pub struct EndSessionTemplate;

/// Account 登录页模板（与 sso/login 类似但用 account 布局）
#[derive(Debug, Template)]
#[template(path = "account/login.html")]
pub struct AccountLoginTemplate {
    pub error: String,
    pub providers: Vec<SocialProvider>,
    pub csrf_token: String,
    pub redirect: String,
}

#[derive(Debug, Template)]
#[template(path = "oidc/confirm_logout.html")]
pub struct ConfirmLogoutTemplate {
    pub csrf_token: String,
    pub session_id: String,
    pub id_token_hint: String,
    pub post_logout_redirect_uri: String,
    pub state: String,
}
