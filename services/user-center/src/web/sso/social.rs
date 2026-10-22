use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::extractor::ClientIp;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use uuid::Uuid;

use crate::db::enums::IdentityKind;
use crate::db::enums::UserStatus;
use crate::service::access::insert_auto_access;
use crate::service::login::LoginService;
use crate::service::social::{
    IdentityResolution, SocialLinkError, SocialLoginError, SocialUserInfo,
};
use crate::state::app::AppState;
use crate::web::login_flow::{LoginFormError, verify_password_for_user};
use crate::web::sso::template::{SocialLinkForm, SocialLinkTemplate};
use crate::web::sso::utility::resolve_auth_request_id;

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(provider_code): Path<String>,
) -> Response {
    let svc = state.social_service();

    let provider = match svc.find_provider_by_code(&provider_code).await {
        Ok(p) => p,
        Err(_) => return Redirect::to("/sso/error?code=unknown_provider").into_response(),
    };

    let auth_request_id = match resolve_auth_request_id(&state, &jar).await {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(%error, "Pending authorization lookup failed");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let prepared = match svc
        .prepare_login_state(&provider, &provider_code, auth_request_id)
        .await
    {
        Ok(p) => p,
        Err(SocialLoginError::ProviderMisconfigured) => {
            return Redirect::to("/sso/error?code=provider_misconfigured").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=internal_error").into_response(),
    };

    let cookies = state.cookie_factory();
    let social_state_cookie = cookies.build_short_lived_cookie(
        &cookies.social_state_cookie_name(),
        &prepared.state_hash,
        state.config.oauth2.auth_code_ttl_seconds,
    );

    (
        jar.add(social_state_cookie),
        Redirect::to(&prepared.authorize_url),
    )
        .into_response()
}

pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    ClientIp(ip): ClientIp,
    Path(provider_code): Path<String>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(err) = params.error {
        tracing::warn!("Social callback error from {provider_code}: {err}");
        return Redirect::to("/sso/error?code=provider_error").into_response();
    }

    let code = match &params.code {
        Some(c) => c.clone(),
        None => return Redirect::to("/sso/error?code=missing_code").into_response(),
    };
    let state_token = match &params.state {
        Some(s) => s.clone(),
        None => return Redirect::to("/sso/error?code=invalid_state").into_response(),
    };

    let state_hash = pero_utils::crypto::sha256_hex(&state_token);

    let cookies = state.cookie_factory();
    let ss_cookie_name = cookies.social_state_cookie_name();
    let cookie_hash = jar.get(&ss_cookie_name).map(|c| c.value().to_owned());
    match cookie_hash {
        Some(h) if pero_utils::crypto::constant_time_eq(h.as_bytes(), state_hash.as_bytes()) => {}
        _ => return Redirect::to("/sso/error?code=invalid_state").into_response(),
    }
    let jar = jar.remove(cookies.clear_cookie(&ss_cookie_name));

    let svc = state.social_service();

    let cb_state = match svc
        .validate_callback_state(&state_hash, &provider_code)
        .await
    {
        Ok(s) => s,
        Err(_) => return Redirect::to("/sso/error?code=invalid_state").into_response(),
    };

    let token_result = match svc
        .exchange_code(
            &cb_state.provider,
            &code,
            &cb_state.social_value.code_verifier,
        )
        .await
    {
        Ok(t) => t,
        Err(SocialLoginError::TokenExchangeFailed(e)) => {
            tracing::error!("Token exchange: {e}");
            return Redirect::to("/sso/error?code=token_exchange_failed").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=token_exchange_failed").into_response(),
    };

    let user_info = match svc
        .fetch_userinfo(
            &cb_state.provider,
            &token_result,
            cb_state.social_value.nonce.as_deref(),
            cb_state.social_value.reauthenticate_after,
        )
        .await
    {
        Ok(u) => u,
        Err(SocialLoginError::Dependency(error)) => {
            tracing::error!(%error, "Upstream signing keys unavailable");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(SocialLoginError::UserinfoFailed(e)) => {
            tracing::error!("Userinfo: {e}");
            return Redirect::to("/sso/error?code=userinfo_failed").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=userinfo_failed").into_response(),
    };

    let authenticated_at = user_info.authenticated_at;
    let resolution = match svc
        .resolve_identity(&cb_state.provider, &user_info, cb_state.auth_request_id)
        .await
    {
        Ok(r) => r,
        Err(SocialLoginError::Internal(e)) => {
            tracing::error!("Identity: {e}");
            return Redirect::to("/sso/error?code=identity_error").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=identity_error").into_response(),
    };

    match resolution {
        IdentityResolution::Resolved { user, identity_id } => {
            finish_social_login(
                &state,
                jar,
                user,
                identity_id,
                cb_state.provider.provider.id,
                &provider_code,
                &SocialLoginContext {
                    auth_request_id: cb_state.auth_request_id,
                    ip,
                    authenticated_at,
                },
            )
            .await
        }
        IdentityResolution::NeedsAccountLink { nonce } => {
            (jar, Redirect::to(&social_link_url(&nonce))).into_response()
        }
        IdentityResolution::NeedsRegistration {
            info,
            auth_request_id,
        } => {
            let (user, identity_id) =
                match register_new_social_user(&state, &cb_state.provider, info, auth_request_id)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("Social registration: {e}");
                        return Redirect::to("/sso/error?code=registration_failed").into_response();
                    }
                };
            finish_social_login(
                &state,
                jar,
                user,
                identity_id,
                cb_state.provider.provider.id,
                &provider_code,
                &SocialLoginContext {
                    auth_request_id,
                    ip,
                    authenticated_at,
                },
            )
            .await
        }
    }
}

pub async fn link_get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<SocialLinkQuery>,
) -> Response {
    let nonce = match query.nonce {
        Some(n) if !n.is_empty() => n,
        _ => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
    };
    render_social_link(&state, jar, &nonce, "").await
}

pub async fn link_post(
    State(state): State<AppState>,
    jar: CookieJar,
    ClientIp(ip): ClientIp,
    Form(form): Form<SocialLinkForm>,
) -> Response {
    let svc = state.social_service();

    let link = match svc.load_social_link(&form.nonce).await {
        Ok(Some(v)) => v,
        Ok(None) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
        Err(SocialLoginError::Internal(e)) => {
            tracing::error!("Load social link: {e}");
            return Redirect::to("/sso/error?code=internal_error").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=internal_error").into_response(),
    };

    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return render_social_link(&state, jar, &form.nonce, "invalid_csrf").await;
    }

    let user_id = match Uuid::parse_str(&link.user_id) {
        Ok(id) => id,
        Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
    };
    let provider_id = match Uuid::parse_str(&link.provider_id) {
        Ok(id) => id,
        Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
    };
    let auth_request_id = match link.auth_request_id.as_deref() {
        Some(raw) => match Uuid::parse_str(raw) {
            Ok(id) => Some(id),
            Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
        },
        None => None,
    };

    let user = match crate::db::entity::users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) if u.deleted_at.is_none() && u.status == UserStatus::Active => u,
        Ok(_) => return render_social_link(&state, jar, &form.nonce, "user_not_found").await,
        Err(e) => {
            tracing::error!("Find social link user: {e}");
            return render_social_link(&state, jar, &form.nonce, "internal_error").await;
        }
    };

    let password_identity = match verify_password_for_user(&state, ip, &user, &form.password).await
    {
        Ok(identity) => identity,
        Err(LoginFormError::ServiceUnavailable) => {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(LoginFormError::Internal) => {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            let key = error.message_key().unwrap_or("invalid_credentials");
            return render_social_link(&state, jar, &form.nonce, key).await;
        }
    };

    let identity_id = match svc
        .link_social_identity(&password_identity, provider_id, &link)
        .await
    {
        Ok(id) => id,
        Err(SocialLinkError::ProviderAlreadyLinked) => {
            return render_social_link(&state, jar, &form.nonce, "provider_already_linked").await;
        }
        Err(SocialLinkError::IdentityTaken) => {
            return render_social_link(&state, jar, &form.nonce, "social_identity_taken").await;
        }
        Err(SocialLinkError::Internal(e)) => {
            tracing::error!("Link social identity: {e}");
            return render_social_link(&state, jar, &form.nonce, "internal_error").await;
        }
    };

    svc.delete_social_link_cache(&form.nonce).await;

    finish_social_login(
        &state,
        jar,
        user,
        identity_id,
        provider_id,
        &link.provider_code,
        &SocialLoginContext {
            auth_request_id,
            ip,
            authenticated_at: None,
        },
    )
    .await
}

#[derive(Debug, serde::Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct SocialLinkQuery {
    pub nonce: Option<String>,
}

async fn register_new_social_user(
    state: &AppState,
    provider: &crate::db::helper::provider::ProviderWithSecret,
    info: SocialUserInfo,
    auth_request_id: Option<Uuid>,
) -> Result<(crate::db::entity::users::Model, Uuid), String> {
    use crate::db::entity::contact_change_requests as ccr;
    use crate::db::entity::{identities, users};
    use crate::db::enums::{ContactChangeStatus, ContactChangeType};

    let txn = state.db.begin().await.map_err(|e| format!("{e}"))?;
    crate::service::provider::require_enabled_social(&txn, provider.provider.id)
        .await
        .map_err(|error| error.to_string())?;
    let now = time::OffsetDateTime::now_utc();
    let user_id = Uuid::now_v7();
    let username = format!("u_{}", user_id.simple());

    users::ActiveModel {
        id: Set(user_id),
        username: Set(username),
        email: Set(if info.email_verified {
            info.email.clone()
        } else {
            None
        }),
        email_verified_at: Set(if info.email_verified { Some(now) } else { None }),
        phone: Set(None),
        phone_verified_at: Set(None),
        nickname: Set(info.name.clone()),
        avatar_url: Set(info.avatar_url.clone()),
        status: Set(UserStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("{e}"))?;

    let identity_id = Uuid::now_v7();
    identities::ActiveModel {
        id: Set(identity_id),
        user_id: Set(user_id),
        provider_id: Set(provider.provider.id),
        kind: Set(IdentityKind::Oauth),
        subject: Set(info.sub.clone()),
        password_hash: Set(None),
        password_algorithm: Set(None),
        password_updated_at: Set(None),
        profile: {
            let mut p = serde_json::json!({
                "email": info.email,
                "email_verified": info.email_verified,
                "name": info.name,
                "picture": info.avatar_url,
            });
            if let serde_json::Value::Object(ref extra) = info.profile_extra
                && let serde_json::Value::Object(ref mut map) = p
            {
                for (k, v) in extra {
                    map.insert(k.clone(), v.clone());
                }
            }
            Set(p)
        },
        last_login_at: Set(Some(now)),
        created_at: Set(now),
        updated_at: Set(now),
        unbound_at: Set(None),
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("{e}"))?;

    insert_auto_access(&txn, user_id, auth_request_id, now)
        .await
        .map_err(|e| format!("auto app access: {e}"))?;

    let pending_email_data =
        if !info.email_verified && !state.config.notification.endpoint.is_empty() {
            if let Some(ref email) = info.email {
                let email_taken = users::Entity::find()
                    .filter(users::Column::Email.eq(email.as_str()))
                    .filter(users::Column::DeletedAt.is_null())
                    .one(&txn)
                    .await
                    .map_err(|e| format!("contact availability query: {e}"))?
                    .is_some();
                let ccr_taken = ccr::Entity::find()
                    .filter(ccr::Column::ChangeType.eq(ContactChangeType::Email))
                    .filter(ccr::Column::NewValue.eq(email.as_str()))
                    .filter(
                        ccr::Column::Status
                            .is_in([ContactChangeStatus::Pending, ContactChangeStatus::Verified]),
                    )
                    .one(&txn)
                    .await
                    .map_err(|e| format!("contact availability query: {e}"))?
                    .is_some();
                if !email_taken && !ccr_taken {
                    let verification = crate::service::verification::generate_code();
                    match (ccr::ActiveModel {
                        id: Set(Uuid::now_v7()),
                        user_id: Set(user_id),
                        change_type: Set(ContactChangeType::Email),
                        new_value: Set(email.clone()),
                        status: Set(ContactChangeStatus::Pending),
                        verification_code_hash: Set(verification.code_hash.clone()),
                        nonce: Set(verification.nonce.clone()),
                        requested_at: Set(now),
                        expires_at: Set(crate::service::verification::expires_in(
                            time::Duration::minutes(15),
                        )),
                        verified_at: Set(None),
                        cancelled_at: Set(None),
                        created_at: Set(now),
                        updated_at: Set(now),
                    })
                    .insert(&txn)
                    .await
                    {
                        Ok(_) => Some((email.clone(), verification.code, verification.nonce)),
                        Err(e) => {
                            tracing::warn!("Social login pending email CCR insert: {e}");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    if let Some((email, code, nonce)) = pending_email_data {
        crate::service::notify::enqueue_verification(
            &txn,
            user_id,
            &state.config.sso.base_url,
            "email",
            &email,
            &code,
            &nonce,
        )
        .await
        .map_err(|_| "notification_queue_failed".to_owned())?;
    }
    txn.commit().await.map_err(|e| format!("{e}"))?;

    let user = users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or("user gone")?;

    Ok((user, identity_id))
}

struct SocialLoginContext {
    auth_request_id: Option<Uuid>,
    ip: Option<ipnetwork::IpNetwork>,
    authenticated_at: Option<time::OffsetDateTime>,
}

async fn finish_social_login(
    state: &AppState,
    jar: CookieJar,
    user: crate::db::entity::users::Model,
    identity_id: Uuid,
    provider_id: Uuid,
    provider_code: &str,
    ctx: &SocialLoginContext,
) -> Response {
    let session_svc = state.session_service();
    let (token, _) = match session_svc
        .create_social(
            user.id,
            identity_id,
            provider_id,
            ctx.ip,
            ctx.authenticated_at,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Session: {e}");
            return Redirect::to("/sso/error?code=internal_error").into_response();
        }
    };

    let login_svc = LoginService::new(&state.db, &state.cache);
    login_svc
        .record_success(
            user.id,
            identity_id,
            Some(provider_id),
            ctx.ip,
            serde_json::json!({"provider": provider_code}),
        )
        .await;

    let cookie = state.cookie_factory().build_session_cookie(&token);
    let redirect_target = if ctx.auth_request_id.is_some() {
        "/oauth2/authorize/resume"
    } else {
        "/account/profile"
    };
    (jar.add(cookie), Redirect::to(redirect_target)).into_response()
}

async fn render_social_link(
    state: &AppState,
    jar: CookieJar,
    nonce: &str,
    error: &str,
) -> Response {
    let svc = state.social_service();

    let link = match svc.load_social_link(nonce).await {
        Ok(Some(v)) => v,
        Ok(None) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
        Err(SocialLoginError::Internal(e)) => {
            tracing::error!("Load social link: {e}");
            return Redirect::to("/sso/error?code=internal_error").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=internal_error").into_response(),
    };

    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    let tpl = SocialLinkTemplate {
        csrf_token,
        nonce: nonce.to_owned(),
        provider_name: link.provider_name,
        account_email: link.email.unwrap_or_default(),
        display_name: link.name.unwrap_or_else(|| "Pero".to_owned()),
        error: error.to_owned(),
    };
    match tpl.render() {
        Ok(html) => (jar, axum::response::Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn social_link_url(nonce: &str) -> String {
    let mut url = "/sso/social/link".to_owned();
    pero_utils::encode::append_query_param(&mut url, "nonce", nonce);
    url
}

fn login_error_url(error: &str) -> String {
    let mut url = "/sso/login".to_owned();
    pero_utils::encode::append_query_param(&mut url, "error", error);
    url
}
