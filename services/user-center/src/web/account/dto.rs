use serde::Deserialize;

use crate::web::util::UserInfo;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountLayout {
    pub user_username: String,
    pub user_name: String,
    pub user_avatar_url: String,
    pub is_admin: bool,
}

impl AccountLayout {
    pub async fn from_user(
        db: &sea_orm::DatabaseConnection,
        user: &crate::db::entity::users::Model,
    ) -> Self {
        let is_admin = crate::web::dashboard::guard::is_dashboard_admin(db, user.id)
            .await
            .unwrap_or_else(|error| {
                // This only controls a navigation link; the dashboard enforces access independently.
                tracing::warn!(%error, "Admin navigation unavailable");
                false
            });
        Self::build(user, is_admin)
    }

    fn build(user: &crate::db::entity::users::Model, is_admin: bool) -> Self {
        let info = UserInfo::from_user(user);
        Self {
            user_username: info.username,
            user_name: info.name,
            user_avatar_url: info.avatar_url,
            is_admin,
        }
    }
}

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
