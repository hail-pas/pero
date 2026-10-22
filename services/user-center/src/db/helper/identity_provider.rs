use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};

use crate::db::entity::identity_providers;
use crate::db::enums::IdentityProviderKind;

pub async fn find_local_provider<C>(db: &C) -> Result<identity_providers::Model, DbErr>
where
    C: ConnectionTrait,
{
    identity_providers::Entity::find()
        .filter(identity_providers::Column::Kind.eq(IdentityProviderKind::Local))
        .one(db)
        .await?
        .ok_or_else(|| DbErr::Custom("local provider not found".into()))
}
