use crate::shared::error::AppError;
use crate::shared::jwt::TokenClaims;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: uuid::Uuid,
    pub roles: Vec<String>,
}

impl AuthUser {
    pub fn from_claims(claims: &TokenClaims) -> Result<Self, AppError> {
        let user_id: uuid::Uuid = claims.sub.parse()
            .map_err(|_| AppError::Unauthorized)?;
        Ok(Self {
            user_id,
            roles: claims.roles.clone(),
        })
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuthUser {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = parts
            .extensions
            .get::<TokenClaims>()
            .ok_or(AppError::Unauthorized)
            .and_then(|claims| Self::from_claims(claims));
        async move { result }
    }
}
