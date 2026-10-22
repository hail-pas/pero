use sea_orm::DatabaseConnection;

pub struct DatabaseGuard {
    db: DatabaseConnection,
}

impl DatabaseGuard {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn shutdown(self) {
        let _ = self.db.close().await;
        tracing::info!("database pool closed");
    }
}
