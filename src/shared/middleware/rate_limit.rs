use axum::body::Body;
use axum::http::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Semaphore;
use tower::Service;

#[derive(Clone)]
pub struct RateLimit<S> {
    pub inner: S,
    pub limiter: Arc<Semaphore>,
}

impl<S> Service<Request<Body>> for RateLimit<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let limiter = self.limiter.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match limiter.try_acquire() {
                Ok(_) => inner.call(req).await,
                Err(_) => {
                    let resp = Response::builder()
                        .status(429)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"code":429001,"message":"rate limit exceeded"}"#,
                        ))
                        .unwrap();
                    Ok(resp)
                }
            }
        })
    }
}
