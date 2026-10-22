//! Logout hints are evidence of a session, never general authentication tokens.
use crate::{
    db::entity::oauth_clients,
    state::{app::AppState, session::SsoSession},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

pub struct LogoutPlan {
    pub needs_confirmation: bool,
    pub redirect: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LogoutError {
    #[error("Invalid logout hint")]
    InvalidHint,
    #[error("Logout dependency unavailable")]
    Dependency(#[from] sea_orm::DbErr),
}

pub async fn prepare(
    state: &AppState,
    token: Option<&str>,
    redirect: Option<&str>,
    callback_state: Option<&str>,
    session: Option<&SsoSession>,
) -> Result<LogoutPlan, LogoutError> {
    let hint = match token.filter(|token| !token.is_empty()) {
        Some(token) => match verify_hint(state, token).await {
            Ok(hint) => Some(hint),
            Err(LogoutError::InvalidHint) => None,
            Err(error) => return Err(error),
        },
        None => None,
    };
    let matches_session = hint
        .as_ref()
        .zip(session)
        .is_some_and(|((_, claims), session)| {
            claims.sub == session.user_id.to_string()
                && claims.sid.as_deref() == Some(session.id.to_string().as_str())
        });
    // Even a valid token for the same user must not silently end another session.
    let needs_confirmation = session.is_some() && !matches_session;
    let redirect = hint.as_ref().and_then(|(client, _)| {
        let redirect = redirect?;
        if !client
            .post_logout_redirect_uris
            .iter()
            .any(|uri| uri == redirect)
            || pero_utils::redirect::validate_oauth_redirect_uri(redirect).is_err()
        {
            return None;
        }
        let mut target = redirect.to_owned();
        if let Some(value) = callback_state {
            pero_utils::encode::append_query_param(&mut target, "state", value);
        }
        Some(target)
    });
    Ok(LogoutPlan {
        needs_confirmation,
        redirect,
    })
}

async fn verify_hint(
    state: &AppState,
    token: &str,
) -> Result<(oauth_clients::Model, pero_utils::oauth::jwt::IdTokenClaims), LogoutError> {
    let kid =
        pero_utils::oauth::jwt::decode_jwt_kid(token).map_err(|_| LogoutError::InvalidHint)?;
    let unverified = pero_utils::oauth::jwt::decode_id_token_claims_unverified(token)
        .map_err(|_| LogoutError::InvalidHint)?;
    if unverified.aud.trim().is_empty() {
        return Err(LogoutError::InvalidHint);
    }
    let key = crate::db::helper::signing_key::find_verification_key_by_kid(&state.db, &kid)
        .await?
        .ok_or(LogoutError::InvalidHint)?;
    let client = oauth_clients::Entity::find()
        .filter(oauth_clients::Column::Identifier.eq(&unverified.aud))
        .one(&state.db)
        .await?
        .ok_or(LogoutError::InvalidHint)?;
    let claims = pero_utils::oauth::jwt::verify_logout_hint(
        token,
        &state.config.oidc.issuer,
        &client.identifier,
        &key.public_key_pem,
    )
    .map_err(|_| LogoutError::InvalidHint)?;
    Ok((client, claims))
}
