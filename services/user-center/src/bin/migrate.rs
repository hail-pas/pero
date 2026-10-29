//! Explicit migration entry point for CI and operators. Service startup uses the same runner.
use sea_orm::{ConnectOptions, Database};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url =
        std::env::var("DATABASE_URL").map_err(|_| "Set DATABASE_URL to the database to migrate")?;
    let mut options = ConnectOptions::new(url);
    options.max_connections(1).sqlx_logging(false);
    let db = Database::connect(options).await?;
    let result = user_center::db::migrate::migrate(&db).await;
    db.close().await?;
    result?;
    println!("Database migration and verification passed");
    Ok(())
}
