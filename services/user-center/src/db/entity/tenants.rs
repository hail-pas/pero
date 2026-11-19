//! SeaORM entity for personal and organization workspaces.
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Clone,Debug,PartialEq,Eq,DeriveEntityModel,Serialize,Deserialize)]
#[sea_orm(table_name="tenants")]
pub struct Model {
    #[sea_orm(primary_key,auto_increment=false)] pub id:Uuid,
    pub kind:String, pub name:String,
    #[sea_orm(column_type="custom(\"citext\")",select_as="text",nullable)] pub slug:Option<String>,
    pub owner_user_id:Option<Uuid>, pub status:String, pub auth_version:i64,
    pub created_at:TimeDateTimeWithTimeZone,pub updated_at:TimeDateTimeWithTimeZone,
}
#[derive(Copy,Clone,Debug,EnumIter,DeriveRelation)] pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
