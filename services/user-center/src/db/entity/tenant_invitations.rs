use sea_orm::entity::prelude::*; use serde::{Deserialize,Serialize};
#[derive(Clone,Debug,PartialEq,Eq,DeriveEntityModel,Serialize,Deserialize)]
#[sea_orm(table_name="tenant_invitations")]
pub struct Model {
    #[sea_orm(primary_key,auto_increment=false)] pub id:Uuid,
    pub tenant_id:Uuid,
    #[sea_orm(column_type="custom(\"citext\")",select_as="text")] pub email:String,
    pub role:String,
    #[serde(skip_serializing)] pub token_hash:String,
    pub status:String,pub invited_by:Option<Uuid>,
    pub expires_at:TimeDateTimeWithTimeZone,
    pub accepted_at:Option<TimeDateTimeWithTimeZone>,
    pub created_at:TimeDateTimeWithTimeZone,
}
#[derive(Copy,Clone,Debug,EnumIter,DeriveRelation)] pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
