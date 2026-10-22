use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct SsoSession {
    pub id: Uuid,
    pub created_at: time::OffsetDateTime,
    pub authenticated_at: time::OffsetDateTime,
    pub user_id: Uuid,
    pub identity_id: Option<Uuid>,
}
