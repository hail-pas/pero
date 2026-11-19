use sea_orm::entity::prelude::*; use serde::{Deserialize,Serialize};
#[derive(Clone,Debug,PartialEq,Eq,DeriveEntityModel,Serialize,Deserialize)]
#[sea_orm(table_name="tenant_members")]
pub struct Model {
    #[sea_orm(primary_key,auto_increment=false)] pub tenant_id:Uuid,
    #[sea_orm(primary_key,auto_increment=false)] pub user_id:Uuid,
    pub role:String,pub status:String,pub auth_version:i64,
    pub joined_at:TimeDateTimeWithTimeZone,pub updated_at:TimeDateTimeWithTimeZone,
}
#[derive(Copy,Clone,Debug,EnumIter,DeriveRelation)] pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
