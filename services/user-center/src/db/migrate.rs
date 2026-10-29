//! One transactional migration path for service startup, bootstrap and the CLI.
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement, TransactionTrait};

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    apply(db, MIGRATIONS, include_str!("verify.sql")).await
}

async fn apply(
    db: &DatabaseConnection,
    migrations: &[(&str, &str)],
    verify: &str,
) -> Result<(), DbErr> {
    let txn = db.begin().await?;
    // Bound lock contention and DDL waits; all pending changes roll back together.
    txn.execute_unprepared("SET LOCAL lock_timeout = '60s'; SET LOCAL statement_timeout = '120s'")
        .await?;
    txn.execute_unprepared("SELECT pg_advisory_xact_lock(hashtext('pero-schema-migrations'))")
        .await?;
    let version = txn
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT current_setting('server_version_num')::integer AS version",
        ))
        .await?
        .ok_or_else(|| DbErr::Custom("PostgreSQL version unavailable".into()))?;
    if version.try_get::<i32>("", "version")? < 180000 {
        return Err(DbErr::Custom("PostgreSQL 18+ required".into()));
    }
    txn.execute_unprepared("CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())").await?;
    let applied = txn
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT version, checksum FROM schema_migrations ORDER BY version",
        ))
        .await?;
    // Applied history must be an exact prefix, including its immutable checksums.
    // Squashed legacy databases deliberately require a fresh database or an explicit operator migration.
    for (index, row) in applied.iter().enumerate() {
        let version: String = row.try_get("", "version")?;
        let checksum: String = row.try_get("", "checksum")?;
        if !migrations.get(index).is_some_and(|(name, sql)| {
            *name == version && pero_utils::crypto::sha256_hex(sql) == checksum
        }) {
            return Err(DbErr::Custom(format!(
                "Migration history/checksum mismatch at {version}; restore the matching release or migrate to a fresh database"
            )));
        }
    }
    for (name, sql) in &migrations[applied.len()..] {
        tracing::info!(migration = name, "applying database migration");
        txn.execute_unprepared(sql).await?;
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)",
            [(*name).into(), pero_utils::crypto::sha256_hex(sql).into()],
        ))
        .await?;
    }
    // Run on every start, even when there are no pending migrations. Fail before serving traffic.
    txn.execute_unprepared(verify).await?;
    txn.commit().await?;
    tracing::info!(
        version = MIGRATIONS.last().map(|m| m.0),
        "database migrations and schema verification passed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
    async fn failed_upgrade_and_verification_roll_back_schema_and_history() {
        let mut url = url::Url::parse(&std::env::var("PERO_TEST_DATABASE_URL").unwrap()).unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.path(), "/pero_security_test");
        let admin = sea_orm::Database::connect(url.as_str()).await.unwrap();
        let schema = format!("migration_{}", uuid::Uuid::now_v7().simple());
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        url.query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema},public"));
        let db = sea_orm::Database::connect(url.as_str()).await.unwrap();
        let initial = (
            "001_test.sql",
            "CREATE TABLE example(id integer PRIMARY KEY)",
        );
        apply(&db, &[initial], "SELECT id FROM example LIMIT 0")
            .await
            .unwrap();
        for (upgrade, verify) in [
            (
                "ALTER TABLE example ADD COLUMN value text; SELECT 1/0",
                "SELECT 1",
            ),
            ("ALTER TABLE example ADD COLUMN value text", "SELECT 1/0"),
        ] {
            assert!(
                apply(&db, &[initial, ("002_test.sql", upgrade)], verify)
                    .await
                    .is_err()
            );
            let row = db.query_one_raw(Statement::from_string(DbBackend::Postgres,
                "SELECT (SELECT count(*) FROM schema_migrations)::bigint AS versions, (SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='example')::bigint AS columns")).await.unwrap().unwrap();
            assert_eq!(row.try_get::<i64>("", "versions").unwrap(), 1);
            assert_eq!(row.try_get::<i64>("", "columns").unwrap(), 1);
        }
        apply(
            &db,
            &[
                initial,
                ("002_test.sql", "ALTER TABLE example ADD COLUMN value text"),
            ],
            "SELECT value FROM example LIMIT 0",
        )
        .await
        .unwrap();
        db.close().await.unwrap();
        admin
            .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
        admin.close().await.unwrap();
    }
}
