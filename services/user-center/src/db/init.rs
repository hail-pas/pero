use std::sync::Arc;

use crate::config::{AppConfig, ENCRYPT_KEY_CONFIG_KEY};
use pero_db_seaorm::DatabaseGuard;
use pero_validate_core::ValidationError;
use sea_orm::DatabaseConnection;

/// 初始化数据库连接池
///
/// 通过 `map_sqlx_postgres_pool_opts` 将 `set_config` 注册到 sqlx pool 级别的 `after_connect`，
/// 确保连接池中的每个连接（包括后续新建的）都会设置 `app.encrypt_key` 会话参数。
///
/// 注意：不能使用 SeaORM 的 `ConnectOptions::after_connect`，因为它只在 pool 创建后
/// 调用一次，不会对后续新建的连接生效。
pub async fn init_db(
    config: &AppConfig,
) -> Result<(DatabaseConnection, DatabaseGuard), ValidationError> {
    config
        .database
        .connect(|opts, extras| {
            opts.sqlx_logging(false);
            let encrypt_key: Arc<str> = Arc::from(extras.encrypt_key.expose_secret());

            opts.map_sqlx_postgres_pool_opts(move |pool_opts| {
                let encrypt_key = Arc::clone(&encrypt_key);

                pool_opts.after_connect(move |conn, _opts| {
                    let encrypt_key = Arc::clone(&encrypt_key);

                    Box::pin(async move {
                        sqlx::query("SELECT set_config($1, $2, false)")
                            .bind(ENCRYPT_KEY_CONFIG_KEY)
                            .bind(encrypt_key.as_ref())
                            .execute(conn)
                            .await?;

                        Ok(())
                    })
                })
            });
        })
        .await
}
