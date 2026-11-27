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

pub fn validate_username(username: &str) -> Result<(), &'static str> {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err("username_required");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username_chars_invalid");
    }
    if !(3..=64).contains(&trimmed.len()) {
        return Err("username_length_invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_username;

    #[test]
    fn username_validation_returns_message_keys() {
        assert_eq!(validate_username("  "), Err("username_required"));
        assert_eq!(validate_username("ab"), Err("username_length_invalid"));
        assert_eq!(
            validate_username(&"a".repeat(65)),
            Err("username_length_invalid")
        );
        assert_eq!(validate_username("中文"), Err("username_chars_invalid"));
        assert_eq!(
            validate_username("member.name"),
            Err("username_chars_invalid")
        );
        assert_eq!(validate_username(" member_1-name "), Ok(()));
    }
}
