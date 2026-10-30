use crate::service::mfa::{Change, change};
use crate::{
    db::entity::{sso_sessions, users},
    service::{ManagementError, security as sec},
    state::app::AppState,
    web::util,
};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize)]
pub struct Input {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub redirect: String,
}
#[derive(Serialize)]
struct SecurityView {
    csrf_token: String,
    layout: super::dto::AccountLayout,
    enabled: bool,
    required: bool,
    pending: bool,
    recovery: bool,
    has_password: bool,
    secret: String,
    qr: String,
    codes: Vec<String>,
    redirect: String,
    error: String,
    providers: Vec<crate::web::sso::dto::SocialProvider>,
    readiness: crate::service::recovery::Readiness,
}
async fn session(state: &AppState, jar: &CookieJar) -> Result<sso_sessions::Model, Response> {
    crate::web::session::extract_browser_session(state, jar)
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(|| Redirect::to("/account/login").into_response())
}
async fn page(
    state: &AppState,
    jar: CookieJar,
    s: &sso_sessions::Model,
    input: &Input,
    codes: Vec<String>,
    error: &str,
) -> Response {
    let user = match users::Entity::find_by_id(s.user_id).one(&state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return Redirect::to("/account/login").into_response(),
        Err(e) => return util::dependency_error(e),
    };
    let layout = match super::dto::AccountLayout::from_user(&state.db, &user).await {
        Ok(layout) => layout,
        Err(error) => return crate::web::util::dependency_error(error),
    };
    let result = async {
        let f = sec::factor(&state.db, s.user_id).await?;
        let required = sec::role(&state.db, s.user_id).await?.is_some();
        let recovery_codes_remaining = f
            .as_ref()
            .filter(|f| f.enabled)
            .map_or(0, |f| f.recovery_hashes.len());
        let enabled = f.as_ref().is_some_and(|f| f.enabled);
        let secret = f
            .filter(|f| {
                f.setup_session == Some(s.id)
                    && f.setup_expires_at > time::OffsetDateTime::now_utc()
            })
            .and_then(|f| f.pending_secret)
            .unwrap_or_default();
        let qr = if secret.is_empty() {
            String::new()
        } else {
            sec::totp(&secret, &user.username.replace(':', "_"))
                .map_err(|_| sea_orm::DbErr::Custom("TOTP config".into()))?
                .to_qr_base64()
                .map_err(|_| sea_orm::DbErr::Custom("QR generation".into()))?
        };
        Ok::<_, sea_orm::DbErr>((required, recovery_codes_remaining, enabled, secret, qr))
    }
    .await;
    let (required, recovery_codes_remaining, enabled, secret, qr) = match result {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let mut providers = match crate::web::sso::utility::find_enabled_social_providers(state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    use crate::db::{
        entity::{identities, identity_providers},
        enums::IdentityProviderKind,
    };
    let bound = identities::Entity::find()
        .filter(identities::Column::UserId.eq(s.user_id))
        .filter(identities::Column::UnboundAt.is_null())
        .find_also_related(identity_providers::Entity)
        .all(&state.db)
        .await;
    let bound = match bound {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    providers.retain(|p| {
        bound.iter().any(|(_, provider)| {
            provider
                .as_ref()
                .is_some_and(|idp| idp.code == p.key && idp.kind == IdentityProviderKind::Oidc)
        })
    });
    let has_password = bound.iter().any(|(identity, _)| {
        identity.kind == crate::db::enums::IdentityKind::Password
            && identity
                .password_hash
                .as_ref()
                .is_some_and(|hash| !hash.is_empty())
    });
    let readiness = crate::service::recovery::readiness(
        &state.config,
        &user,
        has_password,
        !providers.is_empty(),
        recovery_codes_remaining,
    );
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        "SecurityView",
        SecurityView {
            providers,
            readiness,
            layout,
            csrf_token,
            required,
            has_password,
            enabled,
            secret,
            qr,
            codes,
            pending: s.mfa_required && s.mfa_verified_at.is_none(),
            recovery: s.recovery_pending,
            redirect: util::safe_redirect(&input.redirect),
            error: error.into(),
        },
        jar,
    )
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(input): Query<Input>,
    uri: axum::http::Uri,
) -> Response {
    let s = match session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let pending = s.mfa_required && s.mfa_verified_at.is_none() && !s.recovery_pending;
    let challenge_expired = crate::service::mfa::challenge_expired(&s);
    // Unenrolled OIDC administrators must still be able to obtain the fresh
    // upstream proof needed for their first factor enrollment.
    let needs_challenge = if pending && (uri.path() == "/account/reauth" || challenge_expired) {
        match sec::mfa_enabled(&state.db, s.user_id).await {
            Ok(enabled) => enabled,
            Err(e) => return util::dependency_error(e),
        }
    } else {
        false
    };
    if needs_challenge {
        // Primary-only sessions may outlive the challenge window. Reauthenticate
        // before offering an OTP that the service can no longer accept.
        let mut target = "/sso/mfa".to_owned();
        pero_utils::encode::append_query_param(
            &mut target,
            "redirect",
            &util::safe_redirect(&input.redirect),
        );
        if challenge_expired {
            let mut login = "/account/login".to_owned();
            pero_utils::encode::append_query_param(&mut login, "redirect", &target);
            target = login;
        }
        return Redirect::to(&target).into_response();
    }
    if uri.path() == "/sso/mfa"
        && !s.recovery_pending
        && (!s.mfa_required || s.mfa_verified_at.is_some())
    {
        return Redirect::to(&util::safe_redirect(&input.redirect)).into_response();
    }
    page(&state, jar, &s, &input, vec![], "").await
}
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<Input>,
) -> Response {
    if let Some(r) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return r;
    }
    let s = match session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let result = change(&state, &s, &input.action, &input.code, &input.password).await;
    let jar = match result.as_ref().ok().and_then(|r| r.token.as_deref()) {
        Some(token) => jar.add(state.cookie_factory().build_session_cookie(token)),
        None => jar,
    };
    match result {
        Ok(Change {
            codes: Some(codes),
            session_id,
            ..
        }) => {
            let updated = sso_sessions::Entity::find_by_id(session_id)
                .one(&state.db)
                .await;
            match updated {
                Ok(Some(s)) => {
                    let response = page(&state, jar.clone(), &s, &input, codes, "").await;
                    if response.status().is_success() {
                        response
                    } else {
                        (jar, response).into_response()
                    }
                }
                _ => (jar, util::dependency_error("session reload")).into_response(),
            }
        }
        Ok(Change { codes: None, .. }) => {
            (jar, Redirect::to(&util::safe_redirect(&input.redirect))).into_response()
        }
        Err(ManagementError::Invalid(code)) => page(&state, jar, &s, &input, vec![], code).await,
        Err(e) => util::dependency_error(e),
    }
}

pub async fn oidc(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(provider): axum::extract::Path<String>,
    Form(input): Form<Input>,
) -> Response {
    if let Some(r) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return r;
    }
    let s = match session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(e) = crate::service::mfa::ensure_oidc_reauthentication_allowed(&state.db, &s).await {
        return util::management_response(Err(e));
    }
    let result = async {
        use crate::db::{
            entity::identities,
            enums::{IdentityKind, IdentityProviderKind},
        };
        let p = state
            .social_service()
            .find_provider_by_code(&provider)
            .await
            .map_err(|_| ManagementError::Invalid("unknown_provider"))?;
        if p.kind != IdentityProviderKind::Oidc {
            return Err(ManagementError::Invalid("provider_misconfigured"));
        }
        let bound = identities::Entity::find()
            .filter(identities::Column::UserId.eq(s.user_id))
            .filter(identities::Column::ProviderId.eq(p.id))
            .filter(identities::Column::Kind.eq(IdentityKind::Oauth))
            .filter(identities::Column::UnboundAt.is_null())
            .one(&state.db)
            .await?;
        if bound.is_none() {
            return Err(ManagementError::Invalid("unknown_provider"));
        }
        let mut prepared = state
            .social_service()
            .prepare_login_state(&p, &provider, None, &input.redirect, None)
            .await
            .map_err(|_| ManagementError::Invalid("provider_misconfigured"))?;
        let key = crate::cache::key::social_state.key(&prepared.state_hash)?;
        let mut value = state
            .cache
            .get::<crate::cache::key::SocialStateValue>(key)
            .await?
            .ok_or(ManagementError::Invalid("invalid_state"))?;
        value.reauth_session = Some(s.id);
        value.reauthenticate_after = Some(time::OffsetDateTime::now_utc().unix_timestamp());
        state
            .cache
            .set(
                crate::cache::key::social_state.key(&prepared.state_hash)?,
                &value,
            )
            .await?;
        pero_utils::encode::append_query_param(&mut prepared.authorize_url, "prompt", "login");
        pero_utils::encode::append_query_param(&mut prepared.authorize_url, "max_age", "0");
        Ok::<_, ManagementError>(prepared)
    }
    .await;
    match result {
        Ok(p) => {
            let c = state.cookie_factory();
            (
                jar.add(c.build_short_lived_cookie(
                    &c.social_state_cookie_name(),
                    &p.state_hash,
                    300,
                )),
                Redirect::to(&p.authorize_url),
            )
                .into_response()
        }
        Err(e) => util::management_response(Err(e)),
    }
}
