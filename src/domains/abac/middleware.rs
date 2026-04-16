use super::engine;
use super::models::{EvalContext, Policy, PolicyCondition};
use super::repos::PolicyRepo;
use crate::cache;
use crate::shared::error::AppError;
use crate::shared::jwt::TokenClaims;
use crate::shared::state::AppState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

type CachedPolicies = Vec<(Policy, Vec<PolicyCondition>)>;

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

    let cache_key = format!(
        "abac:{}:{}",
        user_id,
        app_id.map(|id| id.to_string()).unwrap_or_default()
    );

    let policies: CachedPolicies = match cache::get_json::<CachedPolicies>(&mut state.cache.clone(), &cache_key).await {
        Ok(Some(cached)) => cached,
        _ => {
            let mut app_policies = PolicyRepo::load_policies_for_app(&state.db, app_id).await?;
            let mut user_policies =
                PolicyRepo::load_user_policies_for_app(&state.db, user_id, app_id).await?;
            app_policies.append(&mut user_policies);
            app_policies.sort_by(|a, b| b.0.priority.cmp(&a.0.priority));

            let _ = cache::set_json(
                &mut state.cache.clone(),
                &cache_key,
                &app_policies,
                state.config.abac.policy_cache_ttl_seconds,
            )
            .await;

            app_policies
        }
    };

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
