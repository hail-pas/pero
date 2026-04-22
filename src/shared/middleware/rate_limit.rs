use crate::shared::response::ApiResponse;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: Instant,
    enabled: bool,
}

impl RateLimiter {
    pub fn new(rps: u64, burst: u64) -> Self {
        let capacity = burst.max(1) as f64;
        let refill_per_second = rps as f64;
        Self {
            inner: Arc::new(Mutex::new(TokenBucket {
                tokens: capacity,
                capacity,
                refill_per_second,
                last_refill: Instant::now(),
                enabled: rps > 0,
            })),
        }
    }

    pub async fn try_acquire(&self) -> bool {
        let mut bucket = self.inner.lock().await;
        if !bucket.enabled {
            return true;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.last_refill = now;
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_per_second).min(bucket.capacity);

        if bucket.tokens < 1.0 {
            return false;
        }

        bucket.tokens -= 1.0;
        true
    }
}

pub async fn rate_limit_middleware(
    State(rate_limiter): State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    if rate_limiter.try_acquire().await {
        return next.run(req).await;
    }

    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(ApiResponse::<()> {
            code: StatusCode::TOO_MANY_REQUESTS.as_u16() as i32 * 100 + 1,
            message: "too many requests".into(),
            data: None,
        }),
    )
        .into_response()
}
