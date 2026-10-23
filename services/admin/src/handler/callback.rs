use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::cookie as handler_cookie;
use crate::oauth2;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    jar: CookieJar,
) -> Response {
    if let Some(err) = &query.error {
        tracing::warn!(error = %err, "OAuth2 authorize error");
        return redirect_login_with_error(err);
    }

    let code = match &query.code {
        Some(c) => c.clone(),
        None => return redirect_login_with_error("missing_code"),
    };

    let expected_state = match jar.get("admin_state") {
        Some(c) => c.value().to_owned(),
        None => return redirect_login_with_error("missing_state_cookie"),
    };
    let received_state = match &query.state {
        Some(s) => s.as_str(),
        None => return redirect_login_with_error("missing_state_param"),
    };
    if expected_state != received_state {
        return redirect_login_with_error("state_mismatch");
    }

    let code_verifier = match jar.get("admin_pkce") {
        Some(c) => c.value().to_owned(),
        None => return redirect_login_with_error("missing_pkce_cookie"),
    };

    let token_resp = match oauth2::exchange_code(
        &state.http,
        &state.config.oauth2.issuer,
        &state.config.oauth2.client_id,
        state.config.oauth2.client_secret.expose_secret(),
        &code,
        &state.config.oauth2.redirect_uri,
        &code_verifier,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Token exchange failed");
            return redirect_login_with_error("token_exchange_failed");
        }
    };

    let id_token_str = match &token_resp.id_token {
        Some(t) => t,
        None => {
            tracing::error!("No id_token in response");
            return redirect_login_with_error("no_id_token");
        }
    };

    let identity = match oauth2::verify_id_token(
        &state.jwks,
        &state.http,
        &state.config.oauth2.issuer,
        &state.config.oauth2.client_id,
        id_token_str,
    )
    .await
    {
        Ok(claims) => claims,
        Err(e) => {
            tracing::error!(error = %e, "ID token verification failed");
            return redirect_login_with_error("id_token_invalid");
        }
    };
    let access = match oauth2::verify_access_token(
        &state.jwks,
        &state.http,
        &state.config.oauth2.issuer,
        &state.config.oauth2.client_id,
        &token_resp.access_token,
    )
    .await
    {
        Ok(claims) => claims,
        Err(e) => {
            tracing::error!(error = %e, "Access token verification failed");
            return redirect_login_with_error("token_exchange_failed");
        }
    };

    let jar =
        handler_cookie::set_auth_cookies(jar, &token_resp, &state.config, access.exp, identity.exp);
    let jar = handler_cookie::clear_flow_cookies(jar, &state.config);

    (jar, (axum::http::StatusCode::FOUND, [("Location", "/")])).into_response()
}

fn redirect_login_with_error(error: &str) -> Response {
    let encoded = pero_utils::encode::percent_encode(error);
    let url = format!("/login?error={}", encoded);
    (axum::http::StatusCode::FOUND, [("Location", url)]).into_response()
}
