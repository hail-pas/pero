use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub actor_id: Uuid,
    pub actor_username: String,
    pub action: String,
    pub target: String,
    #[sea_orm(column_type = "custom(\"inet\")", nullable)]
    pub ip: Option<ipnetwork::IpNetwork>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub outcome: String,
    pub http_status: Option<i32>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
