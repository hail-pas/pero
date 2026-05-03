use crate::shared::constants::cache_keys::CSRF_PREFIX;
use crate::shared::error::AppError;
use crate::shared::kv::{KvStore, KvStoreExt};
use crate::shared::state::AppState;

const CSRF_TTL: i64 = 3600;

pub fn generate_token() -> String {
    crate::shared::utils::random_hex_token()
}

pub async fn create_csrf_token(
    state: &AppState,
    session_id: &str,
) -> Result<String, AppError> {
    let token = generate_token();
    let key = format!("{CSRF_PREFIX}{token}");
    state.repos.kv.set_json(&key, &session_id.to_string(), CSRF_TTL).await?;
    Ok(token)
}

pub async fn verify_csrf_token(
    state: &AppState,
    session_id: &str,
    token: &str,
) -> Result<(), AppError> {
    if token.is_empty() {
        return Err(AppError::BadRequest("missing CSRF token".into()));
    }
    let key = format!("{CSRF_PREFIX}{token}");
    let stored_sid: Option<String> = state.repos.kv.get_json(&key)
        .await
        .ok()
        .flatten();
    match stored_sid {
        Some(sid) if sid == session_id => {
            let _ = state.repos.kv.del(&key).await;
            Ok(())
        }
        Some(_) => Err(AppError::Forbidden("CSRF token session mismatch".into())),
        None => Err(AppError::BadRequest("invalid or expired CSRF token".into())),
    }
}
