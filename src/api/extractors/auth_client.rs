use crate::domain::oauth::models::OAuth2Client;
use crate::shared::error::AppError;

#[derive(Debug, Clone)]
pub struct AuthClient(pub OAuth2Client);

impl std::ops::Deref for AuthClient {
    type Target = OAuth2Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuthClient {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = parts
            .extensions
            .get::<OAuth2Client>()
            .cloned()
            .map(Self)
            .ok_or(AppError::Unauthorized);
        async move { result }
    }
}
