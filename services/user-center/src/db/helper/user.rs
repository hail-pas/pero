use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::db::entity::users;
use crate::db::enums::UserStatus;

pub async fn find_by_identifier(
    db: &DatabaseConnection,
    identifier_type: &str,
    identifier: &str,
) -> Result<Option<users::Model>, sea_orm::DbErr> {
    let col = match identifier_type {
        "email" => users::Column::Email,
        "phone" => users::Column::Phone,
        _ => users::Column::Username,
    };
    users::Entity::find()
        .filter(col.eq(identifier))
        .filter(users::Column::Status.eq(UserStatus::Active))
        .filter(users::Column::DeletedAt.is_null())
        .one(db)
        .await
}

pub fn validate_username(username: &str) -> Result<(), String> {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err("username is required".to_owned());
    }
    if trimmed.len() < 3 || trimmed.len() > 64 {
        return Err("username must be 3-64 characters".to_owned());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username can only contain letters, digits, underscore, and hyphen".to_owned());
    }
    Ok(())
}
