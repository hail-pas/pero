use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let key = rate_limit_key(&req);

    let window_secs: i64 = 60;
    let key = format!("rate_limit:{key}");
    let current = state
        .repos
        .kv
        .get_raw(&key)
        .await?
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
        + 1;
    state
        .repos
        .kv
        .set_raw(&key, serde_json::Value::from(current), window_secs)
        .await?;

    if current > u64::from(state.config.server.rate_limit_rpm) {
        return Err(AppError::RateLimited);
    }

    Ok(next.run(req).await)
}

fn rate_limit_key(req: &Request) -> String {
    if let Some(ip) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
    {
        return ip;
    }
    if let Some(ip) = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
    {
        return ip;
    }
    "anonymous".to_string()
}
