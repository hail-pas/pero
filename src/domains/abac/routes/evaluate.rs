use axum::Json;
use axum::extract::State;
use std::collections::HashMap;

use crate::domains::abac::engine;
use crate::domains::abac::models::{EvalContext, EvaluateRequest, EvaluateResponse};
use crate::domains::abac::repos::PolicyRepo;
use crate::shared::constants::identity;
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::jwt::TokenClaims;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/api/abac/evaluate",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    request_body = EvaluateRequest,
    responses(
        (status = 200, description = "Policy evaluated"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn evaluate(
    State(state): State<AppState>,
    claims: axum::Extension<TokenClaims>,
    ValidatedJson(req): ValidatedJson<EvaluateRequest>,
) -> Result<Json<ApiResponse<EvaluateResponse>>, AppError> {
    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::Unauthorized)?;

    let mut subject_attrs: HashMap<String, Vec<String>> = HashMap::new();
    for (key, value) in PolicyRepo::load_user_attributes(&state.db, user_id).await? {
        subject_attrs.entry(key).or_default().push(value);
    }
    for role in &claims.roles {
        subject_attrs
            .entry(identity::ROLE_ATTR_KEY.to_string())
            .or_default()
            .push(role.clone());
    }

    let policies = PolicyRepo::load_merged_policies(&state.db, user_id, req.app_id).await?;

    let ctx = EvalContext {
        subject_attrs,
        resource: req.resource,
        action: req.action,
        app_id: req.app_id,
    };

    let effect = engine::evaluate(&policies, &ctx, &state.config.abac.default_action);
    let allowed = effect == "allow";

    Ok(Json(ApiResponse::success(EvaluateResponse {
        allowed,
        effect,
    })))
}
