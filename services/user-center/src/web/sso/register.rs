use crate::{service::enrollment, state::app::AppState, web::util};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use enrollment::SocialProof;
use sea_orm::TransactionTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
const SOCIAL_COOKIE: &str = "pero_enrollment_identity";
const FLOW_COOKIE: &str = "pero_enrollment";
#[derive(Default, Deserialize)]
pub struct Params {
    pub token: Option<String>,
    pub app: Option<Uuid>,
    #[serde(default)]
    pub sent: bool,
}
#[derive(Default, Deserialize)]
pub struct Input {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub app: Option<Uuid>,
}
#[derive(Serialize)]
struct View {
    csrf_token: String,
    mode: String,
    app: Option<Uuid>,
    email: String,
    app_name: String,
    status: String,
    reason: String,
    social: bool,
    sent: bool,
}
pub fn flow_token(jar: &CookieJar) -> Option<&str> {
    jar.get(FLOW_COOKIE).map(|c| c.value())
}
pub(crate) fn flow_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((FLOW_COOKIE, token))
        .path("/sso")
        .http_only(true)
        .secure(state.config.sso.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build()
}
fn social_proof(state: &AppState, jar: &CookieJar) -> Option<SocialProof> {
    jar.get(SOCIAL_COOKIE).and_then(|c| {
        pero_utils::crypto::decode_signed_json(
            c.value(),
            state
                .config
                .sso
                .cookie_signing_secret
                .expose_secret()
                .as_bytes(),
        )
        .ok()
    })
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<Params>,
) -> Response {
    if let Some(token) = query.token {
        if let Err(e) = enrollment::progress_by_token(&state.db, &token).await {
            return util::management_response(Err(e));
        }
        return (
            jar.add(flow_cookie(&state, token)),
            Redirect::to("/sso/register"),
        )
            .into_response();
    }
    let app = if query.app.is_some() {
        query.app
    } else {
        match super::utility::resolve_auth_request_id(&state, &jar).await {
            Ok(Some(id)) => {
                use sea_orm::EntityTrait;
                match crate::db::entity::authorization_requests::Entity::find_by_id(id)
                    .one(&state.db)
                    .await
                {
                    Ok(Some(r))
                        if r.expires_at > time::OffsetDateTime::now_utc()
                            && r.completed_at.is_none() =>
                    {
                        Some(r.app_id)
                    }
                    Ok(_) => None,
                    Err(e) => return util::dependency_error(e),
                }
            }
            Ok(None) => None,
            Err(e) => return util::dependency_error(e),
        }
    };
    render(&state, jar, app, query.sent).await
}
async fn render(state: &AppState, jar: CookieJar, app: Option<Uuid>, sent: bool) -> Response {
    let row = if let Some(token) = flow_token(&jar) {
        match enrollment::progress_by_token(&state.db, token).await {
            Ok(r) => Some(r),
            Err(crate::service::ManagementError::Invalid(_)) => None,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        None
    };
    let app = row.as_ref().map(|r| r.app_id).unwrap_or(app);
    let terminal = row.as_ref().is_some_and(|r| {
        matches!(
            r.status.as_str(),
            "completed" | "rejected" | "revoked" | "expired"
        )
    });
    let p = match enrollment::policy(&state.db, if terminal { None } else { app }).await {
        Ok(p) => p,
        Err(e) => return util::management_response(Err(e)),
    };
    let app_name = if let Some(id) = app {
        use sea_orm::EntityTrait;
        match crate::db::entity::apps::Entity::find_by_id(id)
            .one(&state.db)
            .await
        {
            Ok(Some(app)) => app.name,
            Ok(None) => String::new(),
            Err(e) => return util::dependency_error(e),
        }
    } else {
        String::new()
    };
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        "EnrollmentView",
        View {
            csrf_token,
            app,
            mode: if p.emergency_stop {
                "closed".into()
            } else {
                p.mode
            },
            app_name,
            email: row.as_ref().map(|r| r.email.clone()).unwrap_or_default(),
            status: row.as_ref().map(|r| r.status.clone()).unwrap_or_default(),
            reason: row.as_ref().map(|r| r.reason.clone()).unwrap_or_default(),
            social: row.as_ref().is_some_and(|r| r.provider_id.is_some()),
            sent,
        },
        jar,
    )
}
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    pero_api_axum::extractor::ClientIp(ip): pero_api_axum::extractor::ClientIp,
    Form(input): Form<Input>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return e;
    }
    let ip = ip
        .map(|i| i.to_string())
        .unwrap_or_else(|| "unknown".into());
    let key = match pero_cache_redis::rate_limit_key::rl_register_ip.key(&ip) {
        Ok(k) => k,
        Err(e) => return util::dependency_error(e),
    };
    if let Err(e) = pero_cache_redis::enforce_rate_limit(&state.cache, &key, 10).await {
        return match e {
            pero_cache_redis::RateLimitError::Denied { .. } => (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                pero_api_axum::json_error("rate_limited"),
            )
                .into_response(),
            _ => util::dependency_error(e),
        };
    }
    let result = match input.action.as_str() {
        "verify" => match flow_token(&jar) {
            Some(token) => enrollment::verify(&state, token).await,
            None => Err(crate::service::ManagementError::Invalid(
                "enrollment_unavailable",
            )),
        },
        "finalize" => {
            let session = match crate::web::session::extract_session(&state, &jar).await {
                Ok(s) => s,
                Err(e) => return e.into_response(),
            };
            let proof = social_proof(&state, &jar);
            match flow_token(&jar) {
                Some(token) => {
                    enrollment::finalize(
                        &state,
                        token,
                        &input.username,
                        &input.password,
                        session.as_ref(),
                        proof.as_ref(),
                    )
                    .await
                }
                None => Err(crate::service::ManagementError::Invalid(
                    "enrollment_unavailable",
                )),
            }
        }
        "reset" => {
            return (
                jar.remove(Cookie::build(FLOW_COOKIE).path("/sso").build())
                    .remove(Cookie::build(SOCIAL_COOKIE).path("/sso").build()),
                Redirect::to("/sso/register"),
            )
                .into_response();
        }
        "" => {
            let proof = social_proof(&state, &jar);
            if let Some(proof) = proof {
                if !proof.is_fresh() {
                    return util::management_response(Err(
                        crate::service::ManagementError::Invalid(
                            "social_reauthentication_required",
                        ),
                    ));
                }
                let address = match enrollment::email(&input.email) {
                    Ok(v) => v,
                    Err(e) => return util::management_response(Err(e)),
                };
                enrollment::start_social(
                    &state,
                    &address,
                    proof.app,
                    proof.provider,
                    &proof.subject,
                )
                .await
            } else {
                enrollment::start(&state, &input.email, input.app, None).await
            }
        }
        _ => Err(crate::service::ManagementError::Invalid("invalid_request")),
    };
    match result {
        Err(e) => util::management_response(Err(e)),
        Ok(()) if input.action == "finalize" => (
            jar.remove(Cookie::build(FLOW_COOKIE).path("/sso").build())
                .remove(Cookie::build(SOCIAL_COOKIE).path("/sso").build()),
            Redirect::to("/sso/login?registered=1"),
        )
            .into_response(),
        Ok(()) => render(&state, jar, input.app, input.action.is_empty()).await,
    }
}

pub async fn social(
    state: &AppState,
    jar: CookieJar,
    provider: Uuid,
    info: crate::service::social::SocialUserInfo,
    app: Option<Uuid>,
) -> Response {
    if let Err(e) = enrollment::allow_social(&state.db, provider).await {
        return util::management_response(Err(e));
    }
    let proof = SocialProof {
        provider,
        subject: info.sub.clone(),
        proved_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        app,
    };
    let value = match pero_utils::crypto::encode_signed_json(
        &proof,
        state
            .config
            .sso
            .cookie_signing_secret
            .expose_secret()
            .as_bytes(),
    ) {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let cookie = Cookie::build((SOCIAL_COOKIE, value))
        .path("/sso")
        .http_only(true)
        .secure(state.config.sso.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::minutes(10))
        .build();
    let jar = jar.add(cookie);
    let jar = if let Some(token) = flow_token(&jar) {
        match enrollment::lookup(&state.db, token).await {
            Ok(_) => jar,
            Err(crate::service::ManagementError::Invalid(_)) => {
                jar.remove(Cookie::build(FLOW_COOKIE).path("/sso").build())
            }
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        jar
    };
    if let Some(token) = flow_token(&jar) {
        let result = async {
            let txn = state.db.begin().await?;
            crate::service::admin::lock_policy(&txn).await?;
            let row = enrollment::lookup(&txn, token).await?;
            if row.provider_id.is_some()
                && (row.provider_id != Some(provider) || row.subject.as_deref() != Some(&info.sub))
            {
                return Err(crate::service::ManagementError::Invalid(
                    "enrollment_unavailable",
                ));
            }
            if let Some(address) = info.email.as_deref()
                && enrollment::email(address)? != row.email
            {
                return Err(crate::service::ManagementError::Invalid("invalid_email"));
            }
            crate::service::security::execute(
                &txn,
                "UPDATE enrollments SET provider_id=$2,subject=$3 WHERE id=$1",
                vec![row.id.into(), provider.into(), info.sub.into()],
            )
            .await?;
            txn.commit().await?;
            Ok(())
        }
        .await;
        return match result {
            Ok(()) => (jar, Redirect::to("/sso/register")).into_response(),
            Err(e) => util::management_response(Err(e)),
        };
    }
    if let Some(address) = info.email.as_deref() {
        let result = async {
            let address = enrollment::email(address)?;
            enrollment::start_social(state, &address, app, provider, &info.sub).await
        }
        .await;
        return match result {
            Ok(()) => (jar, Redirect::to("/sso/register?sent=true")).into_response(),
            Err(e) => util::management_response(Err(e)),
        };
    }
    let target = app
        .map(|a| format!("/sso/register?app={a}"))
        .unwrap_or_else(|| "/sso/register".into());
    (jar, Redirect::to(&target)).into_response()
}
