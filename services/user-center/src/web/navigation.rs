use sea_orm::DatabaseConnection;

use crate::db::entity::users;
use crate::web::util::UserInfo;

/// One navigation contract for home, account pages and authorized dashboard pages.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserLayout {
    pub user_username: String,
    pub user_name: String,
    pub user_avatar_url: String,
    pub can_access_dashboard: bool,
    pub has_visible_apps: bool,
    pub admin_access: Option<crate::service::permissions::Access>,
}

impl UserLayout {
    pub async fn from_user(
        db: &DatabaseConnection,
        user: &users::Model,
    ) -> Result<Self, sea_orm::DbErr> {
        let allowed = crate::service::admin::can_access_dashboard(db, user.id).await?;
        let mut layout = Self::build(user, allowed);
        if allowed {
            let access = crate::service::permissions::load(db, user.id)
                .await
                .map_err(|error| match error {
                    crate::service::ManagementError::Dependency(error) => error,
                    error => sea_orm::DbErr::Custom(error.to_string()),
                })?;
            layout.has_visible_apps = access.super_admin
                || !access
                    .app_ids(crate::service::permissions::Permission::AppsRead)
                    .is_empty();
            layout.admin_access = Some(access);
        }
        Ok(layout)
    }

    /// Only used after the dashboard middleware has authorized the current request.
    pub(super) fn for_dashboard(user: &users::Model) -> Self {
        Self::build(user, true)
    }

    fn build(user: &users::Model, can_access_dashboard: bool) -> Self {
        let info = UserInfo::from_user(user);
        Self {
            user_username: info.username,
            user_name: info.name,
            user_avatar_url: info.avatar_url,
            can_access_dashboard,
            has_visible_apps: false,
            admin_access: None,
        }
    }
}
