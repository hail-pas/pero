use std::{future::Future, time::Duration};

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use pero_api_axum::ApiResponse;
use serde::Serialize;

use crate::state::app::AppState;

// Below the deployment probe's 3s deadline; both dependencies run concurrently.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
}

pub async fn health() -> ApiResponse<HealthStatus> {
    ApiResponse::success(HealthStatus {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

#[derive(Serialize)]
struct Dependencies {
    database: bool,
    redis: bool,
}

async fn probe<E>(check: impl Future<Output = Result<(), E>>) -> bool {
    matches!(tokio::time::timeout(PROBE_TIMEOUT, check).await, Ok(Ok(())))
}

pub async fn ready(State(state): State<AppState>) -> Response {
    let (database, redis) = tokio::join!(probe(state.db.ping()), probe(state.cache.ping()));
    readiness_response(Dependencies { database, redis })
}

fn readiness_response(dependencies: Dependencies) -> Response {
    let up = dependencies.database && dependencies.redis;
    (
        if up {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(ApiResponse {
            code: if up { 0 } else { 503 },
            message: if up { "success" } else { "unavailable" }.to_owned(),
            data: serde_json::json!({
                "status": if up { "ok" } else { "unavailable" },
                "version": env!("CARGO_PKG_VERSION"),
                "dependencies": dependencies,
            }),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_every_dependency() {
        for (database, redis) in [(true, true), (false, true), (true, false), (false, false)] {
            let response = readiness_response(Dependencies { database, redis });
            assert_eq!(
                response.status(),
                if database && redis {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn probes_bound_stalls_and_report_failures() {
        assert!(probe(async { Ok::<_, ()>(()) }).await);
        assert!(!probe(async { Err::<(), _>(()) }).await);
        let started = std::time::Instant::now();
        let (database, redis) = tokio::join!(
            probe(std::future::pending::<Result<(), ()>>()),
            probe(std::future::pending::<Result<(), ()>>()),
        );
        assert!(!database && !redis);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
