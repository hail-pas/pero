use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::db::entity::identity_provider_keys as ipk;
use crate::db::enums::KeyAlgorithm;
use crate::db::enums::KeyUse;
use crate::db::helper::identity_provider::find_local_provider;
use crate::db::helper::signing_key::apply_verification_key_filter;
use crate::state::app::AppState;

pub async fn jwks(State(state): State<AppState>) -> Response {
    let provider = match find_local_provider(&state.db).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("JWKS: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "local provider not found",
            )
                .into_response();
        }
    };

    let keys = match apply_verification_key_filter(
        ipk::Entity::find()
            .filter(ipk::Column::ProviderId.eq(provider.id))
            .filter(ipk::Column::Use.eq(KeyUse::Sig))
            .filter(ipk::Column::Algorithm.eq(KeyAlgorithm::Rs256)),
    )
    .all(&state.db)
    .await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("JWKS: keys query failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    let jwks: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| {
            let alg_str = "RS256";
            match pero_utils::oauth::jwk::rsa_public_key_to_jwk(&k.public_key_pem, &k.kid, alg_str)
            {
                Ok(jwk) => Some(jwk),
                Err(e) => {
                    tracing::warn!("JWKS: skip key {}: {e}", k.kid);
                    None
                }
            }
        })
        .collect();

    axum::Json(serde_json::json!({"keys": jwks})).into_response()
}
