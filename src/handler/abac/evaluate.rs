use axum::Json;
use axum::extract::State;

use crate::api::extractors::AuthUser;
use crate::api::extractors::ValidatedJson;
use crate::api::response::ApiResponse;
use crate::domain::abac::engine;
use crate::domain::abac::models::{EvalContext, EvaluateRequest, EvaluateResponse, RouteScope};
use crate::domain::abac::resource::{Action, Resource};
use crate::domain::abac::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/api/abac/evaluate",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    request_body = EvaluateRequest,
    responses(
        (status = 200, description = "Policy evaluated", body = ApiResponse<EvaluateResponse>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn evaluate(
    State(state): State<AppState>,
    auth_user: AuthUser,
    ValidatedJson(req): ValidatedJson<EvaluateRequest>,
) -> Result<Json<ApiResponse<EvaluateResponse>>, AppError> {
    let cache_ttl = state.config.abac.policy_cache_ttl_seconds;
    let subject_attrs = service::build_subject_attrs(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        auth_user.user_id,
        &auth_user.roles,
        cache_ttl,
    )
    .await?;
    let policies = service::load_user_policies(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        auth_user.user_id,
        req.app_id,
        false,
        cache_ttl,
    )
    .await?;

    let domain_resource = Resource::from_path(&req.resource);
    let domain_action = Action::from_method_and_path(&req.action, &req.resource);

    let ctx = EvalContext {
        subject_attrs,
        resource: req.resource,
        action: req.action,
        domain_resource: Some(domain_resource),
        domain_action: Some(domain_action),
        app_id: req.app_id,
        route_scope: if req.app_id.is_some() {
            RouteScope::App
        } else {
            RouteScope::Admin
        },
    };

    let effect = engine::evaluate(&policies, &ctx, &state.config.abac.default_action);
    let allowed = effect == "allow";

    Ok(Json(ApiResponse::success(EvaluateResponse {
        allowed,
        effect,
    })))
}
