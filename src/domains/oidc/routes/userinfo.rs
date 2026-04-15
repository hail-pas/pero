use axum::extract::State;
use axum::Json;
use crate::domains::identity::repos::UserRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::AuthUser;
use crate::shared::state::AppState;

pub async fn userinfo(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = UserRepo::find_by_id(&state.db, auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    let mut claims = serde_json::Map::new();
    claims.insert("sub".to_string(), serde_json::Value::String(user.id.to_string()));
    claims.insert("name".to_string(), serde_json::Value::String(user.username.clone()));

    if let Some(nickname) = &user.nickname {
        claims.insert("nickname".to_string(), serde_json::Value::String(nickname.clone()));
    }
    if let Some(avatar) = &user.avatar_url {
        claims.insert("picture".to_string(), serde_json::Value::String(avatar.clone()));
    }
    claims.insert("email".to_string(), serde_json::Value::String(user.email.clone()));
    claims.insert("email_verified".to_string(), serde_json::Value::Bool(true));

    if let Some(phone) = &user.phone {
        claims.insert("phone_number".to_string(), serde_json::Value::String(phone.clone()));
        claims.insert("phone_number_verified".to_string(), serde_json::Value::Bool(true));
    }

    Ok(Json(serde_json::Value::Object(claims)))
}
