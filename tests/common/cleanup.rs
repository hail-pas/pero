use sqlx::postgres::PgPool;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum CleanupItem {
    User(uuid::Uuid),
    App(uuid::Uuid),
    Policy(uuid::Uuid),
    Client(uuid::Uuid),
}

#[allow(dead_code)]
pub(crate) async fn cleanup_user(db: &PgPool, user_id: uuid::Uuid) {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(db)
        .await
        .ok();
}

#[allow(dead_code)]
pub(crate) async fn cleanup_app(db: &PgPool, app_id: uuid::Uuid) {
    sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app_id)
        .execute(db)
        .await
        .ok();
}

#[allow(dead_code)]
pub(crate) async fn cleanup_policy(db: &PgPool, policy_id: uuid::Uuid) {
    sqlx::query("DELETE FROM policies WHERE id = $1")
        .bind(policy_id)
        .execute(db)
        .await
        .ok();
}

#[allow(dead_code)]
pub(crate) async fn cleanup_client(db: &PgPool, client_id: uuid::Uuid) {
    sqlx::query("DELETE FROM oauth2_clients WHERE id = $1")
        .bind(client_id)
        .execute(db)
        .await
        .ok();
}
