use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;

use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

pub async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    match authenticated_user(&state, &jar).await {
        Ok(Some(user)) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Ok(None) => (
            crate::cookie::clear_auth_cookies(jar, &state.config),
            (axum::http::StatusCode::FOUND, [("Location", "/login")]),
        )
            .into_response(),
        Err(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// Only verified identity claims, confirmed by the issuer's online session check,
/// may establish a user.
pub async fn authenticated_user(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<CurrentUser>, pero_error::AppError> {
    let (Some(id_token), Some(access_token)) = (jar.get("admin_it"), jar.get("admin_at")) else {
        return Ok(None);
    };
    let claims = match crate::oauth2::verify_id_token(
        &state.jwks,
        &state.http,
        &state.config.oauth2.issuer,
        &state.config.oauth2.client_id,
        id_token.value(),
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) if error.kind() == pero_error::ErrorKind::Unauthorized => return Ok(None),
        Err(error) => return Err(error),
    };
    let access = match crate::oauth2::verify_access_token(
        &state.jwks,
        &state.http,
        &state.config.oauth2.issuer,
        &state.config.oauth2.client_id,
        access_token.value(),
    )
    .await
    {
        Ok(access) => access,
        Err(error) if error.kind() == pero_error::ErrorKind::Unauthorized => return Ok(None),
        Err(error) => return Err(error),
    };
    // UserInfo validates the presented AT's grant, so first bind it to this RP
    // and the identity's session. A matching subject alone is insufficient.
    if access.sub != claims.sub
        || claims.sid.as_deref().is_none_or(str::is_empty)
        || access.sid != claims.sid
        || claims.at_hash.as_ref().is_some_and(|hash| {
            !pero_utils::crypto::constant_time_eq(
                hash.as_bytes(),
                pero_utils::oauth::jwt::oidc_hash(access_token.value()).as_bytes(),
            )
        })
    {
        return Ok(None);
    }
    let url =
        pero_utils::oauth::url::issuer_endpoint(&state.config.oauth2.issuer, "api/oauth2/userinfo");
    let response = state
        .http
        .get(url)
        .bearer_auth(access_token.value())
        .send()
        .await
        .map_err(|_| {
            pero_error::AppError::dependency_failure(
                "userinfo_unavailable",
                "Identity service unavailable",
            )
        })?;
    if matches!(response.status().as_u16(), 401 | 403) {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(pero_error::AppError::dependency_failure(
            "userinfo_unavailable",
            "Identity service unavailable",
        ));
    }
    #[derive(serde::Deserialize)]
    struct Subject {
        sub: String,
    }
    let subject: Subject = crate::oauth2::bounded_json(response).await.map_err(|_| {
        pero_error::AppError::dependency_failure("userinfo_invalid", "Invalid identity response")
    })?;
    if subject.sub != claims.sub {
        return Ok(None);
    }
    Ok(Some(CurrentUser {
        sub: claims.sub,
        username: claims.preferred_username.unwrap_or_default(),
        email: claims.email,
        name: claims.name,
        picture: claims.picture,
    }))
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CurrentUser>()
            .cloned()
            .ok_or(axum::http::StatusCode::UNAUTHORIZED)
    }
}
