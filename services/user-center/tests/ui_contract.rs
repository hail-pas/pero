use serde_json::{Value, json};
use user_center::db::entity::{
    apps, identity_provider_keys, identity_providers, oauth_clients, users,
};

#[test]
fn browser_dtos_never_serialize_backend_credential_material() {
    let id = uuid::Uuid::now_v7();
    let now = serde_json::to_value(time::OffsetDateTime::UNIX_EPOCH).unwrap();
    let client: oauth_clients::Model = serde_json::from_value(json!({
        "id":id,"app_id":id,"identifier":"test-client","type":"Confidential",
        "secret_hash":"private-hash","redirect_uris":[],"post_logout_redirect_uris":[],
        "scopes":[],"grant_types":[],"require_pkce":true,"access_token_ttl_seconds":7200,
        "refresh_token_ttl_seconds":86400,"id_token_ttl_seconds":7200,"status":"Active","token_version":0,
        "created_at":now,"updated_at":now
    }))
    .unwrap();
    let provider: identity_providers::Model = serde_json::from_value(json!({
        "id":id,"code":"test-provider","name":"Test","kind":"Oidc","scopes":[],
        "settings":{},"enabled":true,"client_secret_enc":"encrypted-client-secret",
        "created_at":now,"updated_at":now
    }))
    .unwrap();
    let key: identity_provider_keys::Model = serde_json::from_value(json!({
        "id":id,"provider_id":id,"kid":"test-key","use":"Sig","algorithm":"Rs256",
        "public_key_pem":"public-material","private_key_pem_enc":"encrypted-private-key",
        "active":false,"created_at":now,"updated_at":now
    }))
    .unwrap();
    let app: apps::Model = serde_json::from_value(json!({
        "id":id,"code":"test-app","name":"Test App","type":"Web","status":"Active",
        "auto_access":false,"system":false,"created_at":now,"updated_at":now
    }))
    .unwrap();
    let user: users::Model = serde_json::from_value(json!({
        "id":id,"username":"test-user","status":"Active","created_at":now,"updated_at":now,
        "email_verified_at":now,"deleted_at":now
    }))
    .unwrap();
    for (model, hidden) in [
        (
            serde_json::to_value(user_center::web::dashboard::dto::AppSummary::from(app)).unwrap(),
            "updated_at",
        ),
        (
            serde_json::to_value(user_center::web::dashboard::dto::UserSummary::from(user))
                .unwrap(),
            "deleted_at",
        ),
        (
            serde_json::to_value(user_center::web::dashboard::dto::ClientSummary::from(
                client,
            ))
            .unwrap(),
            "secret_hash",
        ),
        (
            serde_json::to_value(user_center::web::dashboard::dto::ProviderSummary::from(
                provider,
            ))
            .unwrap(),
            "client_secret_enc",
        ),
        (
            serde_json::to_value(user_center::web::dashboard::dto::KeySummary::from(key)).unwrap(),
            "private_key_pem_enc",
        ),
    ] {
        assert!(model.get(hidden).is_none());
        assert!(model.get("id").is_some_and(Value::is_string));
        if let Some(created_at) = model.get("created_at") {
            assert_eq!(created_at, "1970-01-01T00:00:00Z");
        }
        if let Some(status) = model.get("status") {
            assert_eq!(status, "active");
        }
        if let Some(enabled) = model.get("enabled") {
            assert!(enabled.is_boolean());
            assert_eq!(model["kind"], "oidc");
        }
    }
}
