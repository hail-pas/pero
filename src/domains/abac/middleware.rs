use super::engine;
use super::models::EvalContext;
use super::repos::PolicyRepo;
use crate::shared::error::AppError;
use crate::shared::jwt::TokenClaims;
use crate::shared::state::AppState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

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

    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::Unauthorized)?;

    let app_id = req
        .headers()
        .get("x-app-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Uuid>().ok());

    let subject_attrs = PolicyRepo::load_user_attributes(&state.db, user_id).await?;

    let mut policies = PolicyRepo::load_policies_for_app(&state.db, app_id).await?;
    let mut user_policies =
        PolicyRepo::load_user_policies_for_app(&state.db, user_id, app_id).await?;
    policies.append(&mut user_policies);
    policies.sort_by(|a, b| b.0.priority.cmp(&a.0.priority));

    let ctx = EvalContext {
        subject_attrs,
        resource: path,
        action: req.method().to_string(),
        app_id,
    };

    let effect = engine::evaluate(&policies, &ctx, &state.config.abac.default_action);

    if effect != "allow" {
        tracing::warn!(
            user_id = %claims.sub,
            resource = %ctx.resource,
            action = %ctx.action,
            app_id = ?app_id,
            "ABAC denied access"
        );
        return Err(AppError::Forbidden("access denied by policy".into()));
    }

    Ok(next.run(req).await)
}
