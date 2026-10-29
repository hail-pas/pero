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
        user_center::db::migrate::migrate(db).await.unwrap();
    }

    pub async fn cleanup(self) {
        self.bootstrap
            .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
        self.bootstrap.close().await.unwrap();
    }
}

/// Real authenticated administrator for service-level mutation tests.
#[allow(dead_code)]
pub async fn management_actor(db: &DatabaseConnection) -> user_center::service::permissions::Actor {
    use sea_orm::{DbBackend, Statement};
    let user = Uuid::now_v7();
    let id = Uuid::now_v7();
    for (sql, values) in [
        (
            "INSERT INTO users(id,username) VALUES($1,$2)",
            vec![user.into(), user.to_string().into()],
        ),
        (
            "INSERT INTO admin_roles(user_id,role) VALUES($1,'super_admin')",
            vec![user.into()],
        ),
        (
            "INSERT INTO user_mfa(user_id,secret_enc,enabled) VALUES($1,pgp_sym_encrypt('GEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')),true)",
            vec![user.into()],
        ),
        (
            "INSERT INTO sso_sessions(id,user_id,token_hash,expires_at,mfa_required,mfa_verified_at,reauthenticated_at) VALUES($1,$2,$3,now()+interval '1 day',true,now(),now())",
            vec![id.into(), user.into(), id.to_string().into()],
        ),
    ] {
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .await
        .unwrap();
    }
    user_center::service::permissions::Actor {
        session: user_center::state::session::SsoSession {
            id,
            user_id: user,
            identity_id: None,
            created_at: time::OffsetDateTime::now_utc(),
            authenticated_at: time::OffsetDateTime::now_utc(),
        },
        idle_ttl_seconds: 3600,
    }
}

#[allow(dead_code)]
pub async fn management_context(
    db: &DatabaseConnection,
) -> user_center::web::dashboard::guard::AdminContext {
    use sea_orm::EntityTrait;
    let actor = management_actor(db).await;
    user_center::web::dashboard::guard::AdminContext {
        user: user_center::db::entity::users::Entity::find_by_id(actor.session.user_id)
            .one(db)
            .await
            .unwrap()
            .unwrap(),
        session: actor.session,
        access: user_center::service::permissions::Access {
            super_admin: true,
            ..Default::default()
        },
    }
}
