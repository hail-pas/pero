use crate::{service::security as sec, state::app::AppState, web::util};
use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
pub async fn gate(
    State(state): State<AppState>,
    jar: CookieJar,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if path.starts_with("/static/") || path.starts_with("/.well-known/") {
        return next.run(req).await;
    }
    let session = match crate::web::session::extract_browser_session(&state, &jar).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Some(s) = session {
        let security = matches!(
            path,
            "/account/security" | "/account/reauth" | "/sso/mfa" | "/account/logout"
        ) || path.starts_with("/account/reauth/");
        // Re-running primary authentication must remain possible after an
        // expired MFA challenge, including accounts with only an upstream IdP.
        let primary_login = matches!(
            path,
            "/sso/login" | "/account/login" | "/sso/select-account"
        ) || path.starts_with("/sso/social/")
            && matches!(path.rsplit('/').next(), Some("login" | "callback"));
        // Authorize validates the client and handles prompt=none itself. Its
        // full-session extractor already rejects incomplete MFA and recovery.
        let authorize = path == "/oauth2/authorize";
        if (s.recovery_pending || s.mfa_required && s.mfa_verified_at.is_none())
            && !security
            && !primary_login
            && !authorize
        {
            let target = "/sso/mfa";
            let mut url = target.to_string();
            if req.method() == axum::http::Method::GET {
                pero_utils::encode::append_query_param(
                    &mut url,
                    "redirect",
                    &req.uri().to_string(),
                );
            }
            return Redirect::to(&url).into_response();
        }
        let sensitive = req.method() == axum::http::Method::POST
            && (path.starts_with("/dashboard/")
                || matches!(
                    path,
                    "/account/close"
                        | "/account/profile/change-email"
                        | "/account/profile/change-phone"
                        | "/account/profile/verify-contact"
                        | "/account/change-password"
                )
                || path.starts_with("/account/identities/"));
        if sensitive && !security {
            match sec::recent(&state.db, s.id, state.config.sso.session_idle_ttl_seconds).await {
                Ok(true) => {}
                Ok(false) => {
                    let mut url = "/account/reauth".to_string();
                    let target = if path.starts_with("/dashboard") {
                        "/dashboard"
                    } else {
                        "/account/security"
                    };
                    pero_utils::encode::append_query_param(&mut url, "redirect", target);
                    return Redirect::to(&url).into_response();
                }
                Err(e) => return util::dependency_error(e),
            }
        }
    }
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
