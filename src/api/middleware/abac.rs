use crate::domain::abac::engine;
use crate::domain::abac::models::{EvalContext, RouteScope};
use crate::domain::abac::resource::AbacRouteContext;
use crate::domain::abac::service;
use crate::infra::jwt::TokenClaims;
use crate::shared::constants::headers;
use crate::shared::error::AppError;
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

    let app_id_from_token = claims
        .app_id
        .as_deref()
        .and_then(|s| s.parse::<Uuid>().ok());

    let header_app_id = req
        .headers()
        .get(headers::X_APP_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Uuid>().ok());

    let app_id = match (app_id_from_token, header_app_id) {
        (Some(from_token), Some(from_header)) => {
            if from_token != from_header {
                return Err(AppError::Forbidden(
                    "app_id mismatch between token and header".into(),
                ));
            }
            Some(from_token)
        }
        (Some(from_token), None) => Some(from_token),
        (None, from_header) => from_header,
    };

    let route_scope = req
        .extensions()
        .get::<RouteScope>()
        .copied()
        .ok_or_else(|| AppError::Internal("route missing ABAC scope".into()))?;

    let cache_ttl = state.config.abac.policy_cache_ttl_seconds;
    let subject_attrs = service::build_subject_attrs(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        user_id,
        &claims.roles,
        cache_ttl,
    )
    .await?;
    let policies = service::load_user_policies(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        user_id,
        app_id,
        true,
        cache_ttl,
    )
    .await?;

    let ctx = req
        .extensions()
        .get::<AbacRouteContext>()
        .cloned()
        .ok_or_else(|| {
            tracing::error!(path = %path, "ABAC route missing explicit AbacRouteContext");
            AppError::Internal("route not configured for ABAC".into())
        })?;

    let eval_ctx = EvalContext {
        subject_attrs,
        resource: path,
        action: req.method().to_string(),
        domain_resource: Some(ctx.resource),
        domain_action: Some(ctx.action),
        app_id,
        route_scope,
    };

    let effect = engine::evaluate(&policies, &eval_ctx, &state.config.abac.default_action);

    if effect != "allow" {
        tracing::warn!(
            user_id = %claims.sub,
            resource = %eval_ctx.resource,
            action = %eval_ctx.action,
            app_id = ?app_id,
            "ABAC denied access"
        );
        return Err(AppError::Forbidden("access denied by policy".into()));
    }

    Ok(next.run(req).await)
}
