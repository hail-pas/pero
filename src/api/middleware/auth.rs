use crate::infra::jwt;
use crate::shared::constants::oauth2::TOKEN_TYPE_BEARER_PREFIX;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth_header
        .strip_prefix(TOKEN_TYPE_BEARER_PREFIX)
        .ok_or(AppError::Unauthorized)?
        .trim();

    let claims = jwt::verify_token(token, &state.jwt_keys)?;

    let user_id: uuid::Uuid = claims.sub.parse().map_err(|_| AppError::Unauthorized)?;

    let user = state.repos.users.find_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
