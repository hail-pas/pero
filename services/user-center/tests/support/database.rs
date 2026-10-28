use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use uuid::Uuid;

/// Every scenario owns a schema; concurrent runs never share providers or credentials.
pub struct DatabaseFixture {
    pub url: String,
    bootstrap: DatabaseConnection,
    schema: String,
}

impl DatabaseFixture {
    pub async fn new() -> Self {
        let mut url = url::Url::parse(
            &std::env::var("PERO_TEST_DATABASE_URL").expect("dedicated test database URL"),
        )
        .unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(
            url.path(),
            "/pero_security_test",
            "never run against application data"
        );
        let bootstrap = Database::connect(url.as_str()).await.unwrap();
        let schema = format!("test_{}", Uuid::now_v7().simple());
        bootstrap
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        url.query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema},public"));
        Self {
            url: url.into(),
            bootstrap,
            schema,
        }
    }

    pub async fn migrate(&self, db: &DatabaseConnection) {
        db.execute_unprepared(concat!(
            include_str!("../../migrations/001_init.sql"),
            "\n",
            include_str!("../../migrations/002_audit_events.sql"),
            "\n",
            include_str!("../../migrations/003_mfa_admin_roles.sql"),
            "\n",
            include_str!("../../migrations/004_notification_deliveries.sql"),
            "\n",
            include_str!("../../migrations/005_enrollment.sql")
        ))
        .await
        .unwrap();
    }

    pub async fn cleanup(self) {
        self.bootstrap
            .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
        self.bootstrap.close().await.unwrap();
    }
}
