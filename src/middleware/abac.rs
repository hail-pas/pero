use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use crate::auth::jwt::TokenClaims;
use crate::auth::abac::{self, EvalContext};
use crate::error::AppError;
use crate::state::AppState;

pub async fn abac_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();

    let claims = req
        .extensions()
        .get::<TokenClaims>()
        .ok_or(AppError::Unauthorized)?
        .clone();

    let user_id: uuid::Uuid = claims.sub.parse()
        .map_err(|_| AppError::Unauthorized)?;
    let subject_attrs = abac::load_user_attributes(&state.db, user_id).await?;

    let mut policies = abac::load_policies(&state.db).await?;
    let mut user_policies = abac::load_user_policies(&state.db, user_id).await?;
    policies.append(&mut user_policies);
    policies.sort_by(|a, b| b.0.priority.cmp(&a.0.priority));

    let ctx = EvalContext {
        subject_attrs,
        resource: path,
        action: req.method().to_string(),
    };

    let effect = abac::evaluate(&policies, &ctx, &state.config.abac.default_action);

    if effect != "allow" {
        tracing::warn!(
            user_id = %claims.sub,
            resource = %ctx.resource,
            action = %ctx.action,
            "ABAC denied access"
        );
        return Err(AppError::Forbidden("access denied by policy".into()));
    }

    Ok(next.run(req).await)
}
