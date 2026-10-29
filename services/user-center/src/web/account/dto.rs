use serde::Deserialize;

pub use crate::web::navigation::UserLayout as AccountLayout;

#[derive(Debug, serde::Serialize)]
pub struct ProfileView {
    pub layout: AccountLayout,
    pub user: ProfileUser,
    pub csrf_token: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileUser {
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub phone: String,
    pub phone_verified: bool,
    pub nickname: String,
    pub avatar_url: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    pub pending_email_nonce: String,
    pub pending_email_value: String,
    pub pending_phone_nonce: String,
    pub pending_phone_value: String,
    pub has_password: bool,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct ProfileForm {
    pub csrf_token: String,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct VerifyContactView {
    pub layout: AccountLayout,
    pub csrf_token: String,
    pub change_type: String,
    pub masked_value: String,
    pub nonce: String,
}

#[derive(Debug, serde::Serialize)]
pub struct ChangePasswordView {
    pub layout: AccountLayout,
    pub csrf_token: String,
    pub has_password: bool,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct ChangePasswordForm {
    pub csrf_token: String,
    pub old_password: Option<String>,
    pub new_password: String,
    pub confirm_password: String,
}
