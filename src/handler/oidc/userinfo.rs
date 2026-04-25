use crate::api::extractors::AuthUser;
use crate::domain::identity::store::UserRepo;
use crate::domain::oidc::claims::ScopedClaims;
use crate::shared::error::{AppError, require_found};
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;

#[utoipa::path(
    get,
    path = "/oauth2/userinfo",
    tag = "OIDC",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User info claims"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn userinfo(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = require_found(
        UserRepo::find_by_id(&state.db, auth_user.user_id).await?,
        "user",
    )?;

    let scopes = crate::shared::utils::parse_scopes(auth_user.scope.as_deref());
    let claims = ScopedClaims::from_user_and_scopes(&user, &scopes);

    let mut map = serde_json::Map::new();
    map.insert(
        "sub".to_string(),
        serde_json::Value::String(user.id.to_string()),
    );

    if let Some(v) = claims.name {
        map.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = claims.nickname {
        map.insert("nickname".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = claims.picture {
        map.insert("picture".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = claims.email {
        map.insert("email".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = claims.email_verified {
        map.insert("email_verified".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = claims.phone_number {
        map.insert("phone_number".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = claims.phone_number_verified {
        map.insert(
            "phone_number_verified".to_string(),
            serde_json::Value::Bool(v),
        );
    }

    Ok(Json(serde_json::Value::Object(map)))
}
