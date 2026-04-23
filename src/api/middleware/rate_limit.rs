use crate::infra::cache;
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

    let mut conn = cache::with_conn(&state.cache).await?;

    let window_secs: i64 = 60;
    let script = redis::Script::new(
        r#"
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local current = tonumber(redis.call('INCR', key) or 0)
        if current == 1 then
            redis.call('EXPIRE', key, window)
        end
        if current > limit then
            return 0
        end
        return 1
    "#,
    );

    let allowed: i32 = script
        .key(format!("rate_limit:{key}"))
        .arg(state.config.server.rate_limit_rpm)
        .arg(window_secs)
        .invoke_async(&mut *conn)
        .await?;

    if allowed == 0 {
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
