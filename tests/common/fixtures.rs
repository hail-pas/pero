use crate::common::app::TestApp;
use crate::common::client::send_request;
use crate::common::isolation::{unique_email, unique_name};

#[allow(dead_code)]
pub struct UserFixture {
    pub user_id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[allow(dead_code)]
pub struct AppFixture {
    pub app_id: uuid::Uuid,
    pub name: String,
    pub code: String,
}

#[allow(dead_code)]
pub struct PolicyFixture {
    pub policy_id: uuid::Uuid,
    pub name: String,
}

#[allow(dead_code)]
pub struct ClientFixture {
    pub client_id: uuid::Uuid,
    pub client_id_str: String,
    pub client_secret: String,
}

#[allow(dead_code)]
impl TestApp {
    pub async fn register_default_user(&mut self) -> UserFixture {
        let prefix = "fx";
        let username = unique_name(prefix);
        let email = unique_email(prefix);
        self.register_user(&username, &email, "password123").await
    }

    pub async fn register_user(
        &mut self,
        username: &str,
        email: &str,
        password: &str,
    ) -> UserFixture {
        let (user_id, access_token, refresh_token) =
            register_user_inner(&mut self.app, username, email, password).await;
        self.track_user(user_id);

        UserFixture {
            user_id,
            username: username.to_string(),
            email: email.to_string(),
            access_token,
            refresh_token,
        }
    }

    pub async fn create_test_app(&mut self, token: &str) -> AppFixture {
        let name = unique_name("fxapp");
        let code = unique_name("fxappcode");

        let (status, body) = send_request(
            &mut self.app,
            hyper::Method::POST,
            "/api/apps",
            Some(serde_json::json!({
                "name": name,
                "code": code,
            })),
            Some(token),
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK, "create app failed: {body:?}");
        let app_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
        self.track_app(app_id);

        AppFixture {
            app_id,
            name,
            code,
        }
    }

    pub async fn create_test_client(
        &mut self,
        app_id: uuid::Uuid,
        app_code: &str,
        token: &str,
    ) -> ClientFixture {
        let (status, body) = send_request(
            &mut self.app,
            hyper::Method::POST,
            "/api/oauth2/clients",
            Some(serde_json::json!({
                "app_id": app_id.to_string(),
                "client_name": format!("test_client_{app_code}"),
                "redirect_uris": ["http://localhost:3000/callback"],
                "scopes": ["openid", "profile", "email"],
            })),
            Some(token),
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK, "create client failed: {body:?}");
        let client_id: uuid::Uuid = body["data"]["client"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        self.track_client(client_id);
        let client_id_str = body["data"]["client"]["client_id"]
            .as_str()
            .unwrap()
            .to_string();
        let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

        ClientFixture {
            client_id,
            client_id_str,
            client_secret,
        }
    }

    pub async fn create_test_policy(
        &mut self,
        token: &str,
        effect: &str,
        priority: i32,
    ) -> PolicyFixture {
        let name = unique_name("fxpol");
        let (status, body) = send_request(
            &mut self.app,
            hyper::Method::POST,
            "/api/policies",
            Some(serde_json::json!({
                "name": name,
                "effect": effect,
                "priority": priority,
                "conditions": [],
            })),
            Some(token),
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK, "create policy failed: {body:?}");
        let policy_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
        self.track_policy(policy_id);

        PolicyFixture { policy_id, name }
    }

    pub async fn grant_api_access(&mut self, user_id: uuid::Uuid) {
        let policy_id = uuid::Uuid::new_v4();
        let policy_name = unique_name("test_api_access");

        sqlx::query(
            "INSERT INTO policies (id, name, effect, priority, enabled, app_id) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(policy_id)
        .bind(&policy_name)
        .bind("allow")
        .bind(10_000_i32)
        .bind(true)
        .bind(Option::<uuid::Uuid>::None)
        .execute(&self.db)
        .await
        .expect("failed to seed test access policy");

        for (condition_type, key, operator, value) in [
            ("resource", "path", "wildcard", "/api/**"),
            ("action", "method", "in", "GET,POST,PUT,DELETE"),
        ] {
            sqlx::query(
                "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(policy_id)
            .bind(condition_type)
            .bind(key)
            .bind(operator)
            .bind(value)
            .execute(&self.db)
            .await
            .expect("failed to seed test access policy condition");
        }

        sqlx::query("INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(policy_id)
            .execute(&self.db)
            .await
            .expect("failed to assign test access policy");

        self.track_policy(policy_id);
        self.clear_user_cache(user_id).await;
    }
}

#[allow(dead_code)]
pub async fn register_user_inner(
    app: &mut axum::Router,
    username: &str,
    email: &str,
    password: &str,
) -> (uuid::Uuid, String, String) {
    let (status, body) = send_request(
        app,
        hyper::Method::POST,
        "/api/identity/register",
        Some(serde_json::json!({
            "username": username,
            "email": email,
            "password": password,
        })),
        None,
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK, "register failed: {status} {body:?}");
    let data = body["data"]
        .as_object()
        .expect("missing data in register response");
    let user_id: uuid::Uuid = data["user"]["id"]
        .as_str()
        .expect("missing user.id")
        .parse()
        .expect("invalid user id");
    let access_token = data["access_token"]
        .as_str()
        .expect("missing access_token")
        .to_string();
    let refresh_token = data["refresh_token"]
        .as_str()
        .expect("missing refresh_token")
        .to_string();
    (user_id, access_token, refresh_token)
}

#[allow(dead_code)]
pub async fn login_user_inner(app: &mut axum::Router, username: &str, password: &str) -> String {
    let (status, body) = send_request(
        app,
        hyper::Method::POST,
        "/api/identity/login",
        Some(serde_json::json!({
            "username": username,
            "password": password,
        })),
        None,
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK, "login failed: {status} {body:?}");
    body["data"]["access_token"]
        .as_str()
        .expect("missing access_token")
        .to_string()
}
